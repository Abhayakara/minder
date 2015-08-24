#!/usr/bin/env python3

import dns.resolver
import dns.rdatatype
# This shouldn't be necessary, but for some reason __import__ when
# called from a coroutine, doesn't always work, and I haven't been
# able to figure out why.   Possibly this is a 3.4.0 bug that's fixed
# later, but googling for it hasn't worked.
import dns.rdtypes.ANY.MX
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.NS
import smtp
import ssl as tls
import asyncio
import sys
import pdb
import os
import pwd
import socket
import base64
import hashlib
import time

import mailbox
import email
import email.parser
import email.utils
import email.header

import syslog

from concurrent.futures import FIRST_COMPLETED;

mindhome = "/etc/minder"

# The exchanger class is a controller for the smtp client class that
# takes care of getting a list of mail exchangers for a particular
# domain, connecting to the exchanger for that domain with the best
# preference, and then processing mail to be sent do that domain.
#
# If the exchanger isn't reachable, or if processing encounters a
# temporary failure, the exchanger class takes responsibility for
# storing the message in a local spool for later transmission.

class exchanger(smtp.server):
  remote = None
  domain = None
  sender = None
  sender_status = None
  sender_task = None
  recipients = []
  rcpt_status = []
  rcpt_tasks = []
  state = 0
  CONNECTING = 0
  CONNECTED = 1
  FAILED = 1

  def __init__(self, domain, sender_domain, sender, recipients):
    self.domain = domain
    self.sender = sender
    self.recipients = recipients
    self.state = self.CONNECTING
    task = asyncio.ensure_future(self.get_connection)
    self.connect_task = task
    return self
  
  @asyncio.coroutine
  def get_connection(self):
    try:
      mxs = yield from self.get_exchanger_list()
    except Exception as x:
      if self.connect_task != None and not self.connect_task->cancelled():
        self.connect_task.set_exception(x)
      return
    abp = self.addrs_by_preference(mxs)

    # Try all the exchangers in the highest preference tier in
    # quick succession, waiting only five seconds for a successful
    # connect before launching the next attempt.  If all of those time
    # out, then we try the next tier, and so on until we run out.
    for addrs in abp:
      connection = yield from self.connect_to_addresses(addrs, 5)
      self.remote = connection

      if connection != None:
        self.sender_task = yield from connection.send_mailfrom(self.mailfrom)
        return True
    return False

  # We may not have had a complete list of senders when we started,
  # IWC we can add some more later.
  def add_sender(self, sender):
    

  @asyncio.coroutine
  def add_sender_worker(self, sender):
    
  @asyncio.coroutine
  def get_exchanger_list(self):
    resolver = dns.resolver.Resolver()
    resolver.use_edns(0, 0, 1410)
    mxs = {}
    answer = None
    addressable = False
    try:
      answer = yield from resolver.aquery(domain, "MX")
      
    except dns.resolver.NoAnswer:
      # No answer means there's no MX record, so look for an A or
      # AAAA record.
      arecs = []
      a4recs = []
      yield from self.fetch_addrs(resolver, domain, arecs, a4recs)
      if len(arecs) > 0 or len(a4recs) > 0:
        mxs = { 0: [ { "exchange" : domain,
                       "a": arecs, "aaaa": a4recs } ] }
        addressable = True

    except NXDOMAIN:
      self.push("550 no such domain.")
      syslog.syslog(syslog.LOG_INFO, "550 no such domain: %s" % domain)
      print("550 no such domain: %s" % domain)
      return False

    except:
      return True

    else:
      for mx in answer:
        if mx.rdtype == dns.rdatatype.MX:
          arecs = []
          a4recs = []
          # If exchange addresses were included in the additional
          # section, use those.
          for rrset in answer.response.additional:
            if rrset.name == mx.exchange:
              if rrset.rdtype == dns.rdatatype.A:
                for rdata in rrset:
                  arecs.append(rdata.address)
              elif rrset.rdtype == dns.rdatatype.AAAA:
                for rdata in rrset:
                  a4recs.append(rdata.address)
          # Otherwise, fetch A and/or AAAA records for exchange
          if len(arecs) == 0 and len(a4recs) == 0:
            yield from self.fetch_addrs(resolver, mx.exchange, arecs, a4recs)
          if len(arecs) > 0 or len(a4recs) > 0:
            entry = { "exchange": mx.exchange,
                      "a": arecs, "aaaa": a4recs}
            if mx.preference in mxs:
              mxs[mx.preference].append(entry)
            else:
              mxs[mx.preference] = [entry]
            addressable = True

    # If we didn't get a single server IP address either out of the
    # MX query chain or the A/AAAA query on the name if there was no
    # MX, then we can't deliver to this address.
    if not addressable:
      raise smtp.PermanentFailure(code=550,
                                  data=["no exchanger/address for domain"])
          
    return mxs
  
  # Make a list of all the addresses to try, in order of preference.
  # We prefer IPv6 for the first attempt, but interleave IPv6 and
  # IPv4 addresses in case one transport is working and the other
  # is not.   The interleaving is per-exchange, so we always try
  # exchanges in order of preference and, among exchanges with the
  # same preference, one exchange at a time.
  def compute_address_list(self, mxs):
    abp = []
    preferences = list(mxs.keys())
    preferences.sort()
    # Iterate across preference levels
    for pref in preferences:
      addrs = []
      abp.append(addrs)
      exchanges = mxs[pref]
      # Iterate across exchanges at a given preference level
      for exchange in exchanges:
        arecs = exchange['a']
        qrecs = exchange['aaaa']
        name = exchange['exchange']
        # Interleave the IPv6 and IPv4 addresses for this exchange.
        lim = max(len(arecs), len(qrecs))
        for i in range(0, lim):
          if i < len(qrecs):
            addrs.append((qrecs[i], socket.AF_INET6, name))
          if i < len(arecs):
            addrs.append((arecs[i], socket.AF_INET, name))
    return abp

  # Try all of the exchangers until we connect to one, or until all of
  # the attempts time out.  The reason for the short startup times is
  # that we don't know that our chosen exchanger is reachable; e.g.,
  # we might only have IPv4 or only IPv6, and so an exchanger that's
  # running the unsupported transport is going to either time out or
  # return an error; if it doesn't return an immediate error, we don't
  # want to wait the whole 90 seconds.
  #
  # It should be rare that a connection takes longer than five
  # seconds to complete if the exchange is reachable.
  @asyncio.coroutine
  def connect_to_addresses(self, addresses, interval):
    tasks = []
    connection = None

    # Loop through the addresses, starting a connection to the next
    # one every _interval_ seconds.   When we have a connection,
    # wait for it to become ready.
    for (address, family, name) in addresses:
      print("Connecting to", name, "at", address)
      loop = asyncio.get_event_loop()
      client = smtp.client(self.sender_domain, address, family, 25)
      tasks.append(client.is_ready())
      # See if any of the task(s) we've launched have completed.
      connection = yield from process_completions(time.time() + interval,
                                                  tasks)
      if connection:
        break

    # At this point if we don't have a connection, but still have pending
    # tasks, wait up to an additional _interval_ seconds for one of them to
    # cough up a connection.
    if connection == None:
      connection = yield from process_completions(time.time() + interval)
      for task in tasks:
        task.cancel() # we should do a clean shutdown.

      # Still nothing.   Too bad.
      if connection == None:
        return None
    if connection != None:
      print("Connected to:", repr(connection.peer))
    return connection

  # process_completions is a worker function which takes a list of
  # attempted connections.  If we get any kind of exception while
  # connecting or doing the initial handshakes, we discard the
  # connection.  In principle this could be bad if all of the
  # exchangers return a permanent failure of some kind, but that is
  # either a misconfiguration, or else they hate us specifically;
  # either condition can only be assumed to be temporary.
  #
  # If any connection gets through to the point where it has responded
  # to the EHLO/HELO with a success status, we return that connection;
  # otherwise, if the given timeout expires, we return, leaving it to the
  # caller to either keep trying, or cancel the outstanding tasks.

  @asyncio.coroutine
  def process_completions(timeout, connects):
    connection = None
    while connection == None and len(connects) > 0:
      # Figure out how much time to wait, wait at least a
      # bit.
      remaining = timeout - time.time()
      if remaining < 0:
        remaining = 0.1

      alltasks = connects.copy()
      co2 = asyncio.wait(alltasks,
                         timeout=interval, return_when=FIRST_COMPLETED)

      # Wait up to _interval_ seconds for this task or any task created in a
      # previous iteration to complete.
      (complete, pending) = yield from co2

      # if any tasks completed, try to establish a conversation on the
      # corresponding socket.
      for task in complete:
        # If the task didn't get an exception or get cancelled, then we
        # should have a connected socket ready to take commands.
        if !task.cancelled() and task.exception() == None:
          connection = task.result()

        connects.remove(task)

      if timeout <= time.time():
        break
    return connection
  
  # Do the A and AAAA queries in parallel.
  @asyncio.coroutine
  def fetch_addrs(self, resolver, name, arecs, a4recs):
    aco = resolver.aquery(name, "A", raise_on_no_answer=False)
    a4co = resolver.aquery(name, "AAAA", raise_on_no_answer=False)
    co = asyncio.gather(aco, a4co)
    (aans, a4ans) = yield from co
    if aans.rrset != None:
      for rdata in aans:
        arecs.append(rdata.address)
    if a4ans.rrset != None:
      for rdata in a4ans:
        a4recs.append(rdata.address)
    
  def send_data(self, chunk):
    
