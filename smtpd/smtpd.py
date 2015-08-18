#!/usr/bin/env python3

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

import mailbox
import email
import email.parser
import email.utils
import email.header

import syslog

from concurrent.futures import FIRST_COMPLETED;

mindhome = "/etc/minder"

class coldb:
  def parsefile(self, filename):
    cf = open(filename, "r")
    for line in cf:
      line = line.rstrip()
      fields = line.split(":")
      self.process_fields(fields)
    cf.close()
      
class tlsconf(coldb):
  tlsctx = None
  cert = None
  key = None
  name = None

  def __init__(self, conffile=(mindhome + "/tls.conf")):
    self.parsefile(conffile)

    # TLS Context for incoming TLS connections:
    # XXX this should be in a separate process!
    # It may seem a bit contrary to practice that which ciphers and
    # protocols are supported is hardcoded.   The reason for this is
    # that the end-user doesn't know from ciphers and protocols, and
    # so we choose as secure a selection as we can.
    #
    # This is arguably problematic, because we might prefer crappy
    # security to no security for TLS delivery, but we demand good
    # security for maildrops, and have no way to distinguish whether
    # this is a maildrop or a transfer until _after_ the TLS
    # connection is established.
    #
    # Once STARTTLS support is implemented, we could allow
    # maildrops only on the TLS port (465), and reject maildrops on
    # the main port (25) and the STARTTLS port (587).
    self.tlsctx = tls.SSLContext(tls.PROTOCOL_TLSv1)
    self.tlsctx.options = (tls.OP_NO_COMPRESSION | tls.OP_SINGLE_DH_USE |
                           tls.OP_SINGLE_ECDH_USE |
                           tls.OP_CIPHER_SERVER_PREFERENCE |
                           tls.OP_NO_SSLv2 | tls.OP_NO_SSLv3 | tls.OP_NO_TLSv1)
    self.tlsctx.verify_mode = tls.CERT_NONE # we don't want client certs
    self.tlsctx.set_ciphers("ECDH+AESGCM:DH+AESGCM:ECDH+AES256:DH+AES256:" +
                            "ECDH+AES128:DH+AES:ECDH+3DES:DH+3DES:" +
                            "RSA+AESGCM:RSA+AES:RSA+3DES:!aNULL:!MD5")
    self.tlsctx.load_cert_chain(self.cert, self.key)

  def process_fields(self, fields):
    if fields[0] == "name":
      self.name = fields[1]
      count = 2
    elif fields[0] == "cert":
      self.cert = fields[1]
      count = 2
    elif fields[0] == "key":
      self.key = fields[1]
      count = 2
    else:
      raise Exception("Unknown TLS setting: ", ":".join(fields))
    if len(fields) > count:
      raise Exception("Too many fields: ", ":".join(fields))

class userdb(coldb):
  users = {}
  domains = []
  wildcard_domains = []

  def __init__(self):
    self.parsefile(mindhome + "/userdb")
    
  def authenticate(self, username, password):
    # Treat the username and password as if they are UTF-8.
    # Encoding is not well specified here, so this could cause
    # interop problems.
    address = self.parse_address(str(username, encoding="utf-8"))
    if address == None:
      return None
    if address[0] not in self.users:
      return None
    # Find the user entry for the given domain.   If a user's
    # domain is expressed as a wildcard, we prepend "*." to the
    # domain we parsed out of the authentication data to find it,
    # since it would be bogus to try to explain to the user why
    # their username is jruser@*.example.com.
    udmap = self.users[address[0]]
    if address[1] not in udmap:
      if "*." + address[1] in udmap:
        udata = udmap["*." + address[1]]
      else:
        return None
    else:
      udata = udmap[address[1]]
    hash = base64.standard_b64decode(udata["pass"])
    salt = hash[32:]
    sha = hashlib.sha256()
    sha.update(password)
    sha.update(salt)
    chash = sha.digest()
    # We return the mailbox so that we can use it to validate
    # outgoing addresses later--any incoming address that winds
    # up in the mailbox of the user who validated is a valid
    # outgoing email address for that user.
    if chash == hash[:32]:
      return udata["mbox"]
    return None

  def process_fields(self, fields):
    # user:mailbox:password:domains...
    if len(fields) < 4:
      raise Exception("invalid user database entry: %s" % line)
    user = fields[0]
    mbox = fields[1]
    passw = fields[2]
    udomains = fields[3:]
    if user in self.users:
      udmap = users[user]
    else:
      udmap = {}
    for domain in udomains:
      udmap[domain] = {'mbox': mbox, 'pass': passw}
      if domain[0] == '*' and domain[1] == '.':
        if domain not in self.wildcard_domains:
          self.wildcard_domains.append(domain)
      elif domain not in self.domains:
        self.domains.append(domain)
    self.users[user] = udmap

  def parse_address(self, address):
    # Python's parseaddr function doesn't actually do the right thing
    # here, so for now this is going to be a very manual process,
    # more's the pity.
    # XXX does this work with unicode?
    parts = address.lower().split("@")
    if len(parts) != 2:
      return None
    user = parts[0]
    domain = parts[1]
    return [user, domain]

  def find_wildcard(self, subdomain, domains):
      splode = subdomain.split(".")
      for i in range(0, len(splode)):
        wildsub = "*." + ".".join(splode[i:])
        if wildsub in domains:
          return wildsub
      return None
    
  def validate_domain(self, address):
    # assume address is output of parse_address
    domain = address[1]
    if domain not in self.domains:
      wildcard = self.find_wildcard(domain, self.wildcard_domains)
      if wildcard != None:
        return True
      return False
    else:
      return True

  def find_slot(self, address):
    user = address[0]
    domain = address[1]
    if user not in self.users:
      return None
    udomains = self.users[user]
    for udomain in udomains:
      if domain == udomain:
        return udomains[udomain]
    wildcard = self.find_wildcard(domain, udomains)
    if wildcard != None:
      return udomains[wildcard]
    return None

  def validate_address(self, address):
    slot = self.find_slot(address)
    if slot == None:
      return False
    return True

class msmtp(smtp.server):
  userdb = None
  mailbox = None

  # If we are authenticated, make sure the mail is from
  # the authenticated user; if not, make sure that the
  # sender passes basic anti-spam checks.
  def validate_mailfrom(self, address):
    if self.authenticated:
      return validate_fromuser(self, address)
    else:
      return validate_sender(self, address)

  def validate_sender(self, address):
    # Add sender validation fu here:
    return True

  def validate_fromuser(self, address):
    # First just check that it's a valid local address
    if not self.validate_mailbox(address):
      return False
    
    # Now check to see if the address delivers to the
    # specified mailbox, which should be the mailbox
    # of the authenticated user.
    addr = self.userdb.parse_address(address)
    slot = self.userdb.find_slot(addr)
    if (self.mailbox != None and self.authenticated and
        slot["mbox"] == self.mailbox):
      return True
    return False

  def validate_rcptto(self, address):
    udbaddr = self.userdb.parse_address(address)
    if udbaddr == None:
      self.push("501 Syntax: RCPT TO: <address>")
      syslog.syslog(syslog.LOG_INFO, "501 Syntax: RCPT TO: %s" % address)
      return False
    
    if self.authenticated:
      return self.validate_recipient(udbaddr[0], udbaddr[1])
    else:
      return self.validate_mailbox(udbaddr)
      
  # Do the A and AAAA queries in parallel.
  def fetch_addrs(self, name, arecs, a4recs):
    aco = resolver.aquery(name, "A", raise_on_no_answer=False)
    a4co = resolver.aquery(name, "AAAA", raise_on_no_answer=False)
    co = asyncio.gather([aco, a4co])
    (aans, a4ans) = yield from co
    for rdata in aans:
      arecs.append(rdata.address)
    for rdata in a4ans:
      a4recs.append(rdata.address)
    
  # Do all the MX fiddling to get a connection to the specified domain
  # if we don't already have one.
  @asyncio.coroutine
  def get_connection(self, domain):
    # We're already connected.   Just return the connection.
    if domain in self.connections:
      return True
    
    resolver = dns.resolver.resolver()
    resolver.use_edns(0, 0, 1410)
    mxs = {}
    answer = None
    addressable = False
    try:
      answer = yield from resolver.aquery(domain, "MX")
      
    except NoAnswer:
      # No answer means there's no MX record, so look for an A or
      # AAAA record.
      arecs = []
      a4recs = []
      self.fetch_addrs(domain, arecs, a4recs)
      if len(arecs) > 0 or len(a4recs) > 0:
        mxs = { 0: { "exchange" : domain,
                     "a": arecs, "aaaa": a4recs } }
        addressable = True

    except NXDOMAIN:
      self.push("550 no such domain.")
      syslog.syslog(syslog.LOG_INFO, "550 no such domain: %s" % domain)
      return False

    except:
      # Temporary failure; we just have to stash the message for this
      # address.
      self.connections[user + "@" + domain] = None
      self.connections[domain] = None
      return True

    else:
      for mx in answer:
        arecs = []
        a4recs = []
        # If exchange addresses were included in the additional
        # section, use those.
        for rdata in answer.response.additional:
          if rdata.name == mx.exchange:
            if rdata.type == dns.rdatatype.A:
              arecs.append(rdata.address)
            elif rdata.type == dns.rdatatype.AAAA:
              a4recs.append(rdata.address)
        # Otherwise, fetch A and/or AAAA records for exchange
        if len(arecs) == 0 and len(a4recs) == 0:
          self.fetch_addrs(mx.exchange, arecs, a4recs)
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
      self.push("550 no exchanger or addresses for domain.")
      syslog.syslog(syslog.LOG_INFO,
                    "550 no exchanger or addresses for: %s" % domain)
      return False
          
    # Our task now is to get a connection to the most preferable
    # Mail Exchanger (MX) we can reach.
    # Make a list of all the addresses to try, in order of preference.
    # We prefer IPv6 for the first attempt, but interleave IPv6 and
    # IPv4 addresses in case one transport is working and the other
    # is not.   The interleaving is per-exchange, so we always try
    # exchanges in order of preference and, among exchanges with the
    # same preference, one exchange at a time.

    addrs = []
    preferences = list(keys(mxs))
    preferences.sort()
    # Iterate across preference levels
    for pref in preferences:
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

    # Time is of the essence here, because the mail user agent is
    # waiting, and we want to give the user quick feedback, but we
    # also want to follow the rules and not boost our spam score
    # by delivering to a low-preference MX, so we allow about five
    # seconds to complete a connection rather than the usual 90
    # seconds.   We start connecting every five seconds, and take
    # the first connection that completes, dropping the others.
    # It should be rare that a connection takes longer than five
    # seconds to complete if the exchange is reachable.
    try:
      connection = self.connect_to_addresses(addrs, 5,
					     self.initialize_connection)
    except smtp.TemporaryFailure as x:
      # Temporary failure; we just have to stash the message for this
      # address.
      self.connections[user + "@" + domain] = None
      self.connections[domain] = None
      return True
    except smtp.PermanentFailure as x:
      self.push("550 " + str(x))
      # Remember the exception in case there's another RCPT TO:
      # for this domain.
      self.connections[user + "@" + domain] = x
      self.connections[domain] = x
    self.connections[user + "@" + domain] = connection
    self.connections[domain] = connection
    return True

  @asyncio.coroutine
  def connect_to_addresses(self, addresses, interval, initialize):
    tasks = []
    client_futs = []
    connection = None

    # Loop through the addresses, starting a connection to the next
    # one every _interval_ seconds.   When we have a connection,
    # wait for it to become ready.
    for (address, family, name) in addresses:
      print("Connecting to", name, "at", address)
      co = asyncio.create_connection(smtp.client, host=address, port=25, family=family)
      task = asyncio.ensure_future(co)
      tasks.append(task)
      alltasks = tasks.copy().extend(client_futs)
      co2 = asyncio.wait(alltasks, timeout=interval, return_when=concurrent.futures.FIRST_COMPLETED)
      # Wait up to _interval_ seconds for this task or any task created in a
      # previous iteration to complete.
      (complete, pending) = yield from co2
      # if any tasks completed, try to establish a conversation on the
      # corresponding socket.
      for task in complete:
        # If the future was cancelled, it was by something at a higher
        # level, so we should just stop.
        if task.cancelled():
          return
        # If we didn't get an exception, then we should have a connected
        # socket.
        if task.exception() == None:
          if task in tasks:
            (transport, client) = task.result()
            fut = client.is_ready()
            if fut == None:
              connection = client
            else:
              client_futs.append(fut)
          elif task in client_futs:
            connection = task.result()
          else:
            print("Weird: %s completed but not in %s or %s" % (task, tasks, client_futs))
        if task in tasks:
          tasks.remove(task)
        else:
          client_futs.remove(task)
        if connection != None:
          break
            
    # Identify the sender of the current transaction.
    yield from connection.mail_from(self.mail_from)
    return connection

  # In validate_recipient, we actually try to connect to the mail
  # server for the specified recipient.   If more than one recipient
  # for a message is on the same server (as identified by the
  # domain) we use the same connection to validate both recipients.
  # When we have validated all the recipients and have a message to
  # deliver, we write it to a special mailbox, and then put a link
  # in the mailbox for each recipient.  Then we try to deliver, and
  # on each acknowledged delivery we erase that recipient.   If we
  # deliver to all the recipients, we erase the stored message.
  # If some recipients have transient errors, then we hold the
  # message for later delivery to those recipients, but the goal is
  # to return as much status information to the sender in realtime
  # as possible.   Store-and-forward may be necessary for some
  # locales where network connectivity is poor, but should not
  # be necessary in most cases.
  @asyncio.coroutine
  def validate_recipient(self, user, domain):
    # If we get a False back from get_connection, it means we
    # invalidated the sender and sent a 550 response.
    if not (yield from self.get_connection(domain)):
      return False

    # Otherwise, see if there's a connection.   There will either
    # be a connection or None for this domain.
    connection = self.connections[domain]

    # None means that we weren't able to connect because of a
    # temporary failure, which means we have to assume the address
    # is valid and try to deliver it later, generating a bounce if
    # worse comes to worst.
    if connection == None:
      return True
    
    return (yield from connection.send_rcpt_to(user + "@" + domain))
    
  def validate_mailbox(self, address):
    if not self.userdb.validate_domain(address):
      self.push('551 Not a local domain, relaying not available.')
      syslog.syslog(syslog.LOG_INFO,
		    "551 Invalid domain: RCPT TO: %s@%s" % address)
      return False

    if not self.userdb.validate_address(address):
      self.push("550 Mailbox unavailable.")
      syslog.syslog(syslog.LOG_INFO,
		    "550 Invalid mailbox: RCPT TO: %s@%s" % address)
      return False
    return True

  def process_message(self, peer, mailfrom, rcpttos, data):
    syslog.syslog(syslog.LOG_INFO, "Mail from %s via %s" % (mailfrom, peer[0]))
    boxes = {}
    self.debugstream.flush()
    rcvd = "Received: from %s; %s\r\n" % (peer[0], email.utils.formatdate())
    #parser = email.parser.Parser()
    #message = None
    #try:
    #  message = parser.parsestr(rcvd + data)
    #except Exception as e:
    #  syslog.syslog(syslog.LOG_INFO, "Malformed message: %s", str(e))

    #if message != None:
    for rcpt in rcpttos:
      syslog.syslog(syslog.LOG_INFO, "Delivering to %s" % rcpt)
      address = self.userdb.parse_address(rcpt)
      if address == None:
        raise Exception("Validated address fails to parse: %s\n" % rcpt)
      slot = self.userdb.find_slot(address)
      if slot == None:
        raise Exception("Validated address has no slot: %s\n" % rcpt)
      if "mbox" not in slot:
        raise Exception("No mailbox for address %s\n" % rcpt)
      maildir = mailbox.Maildir("/mailboxes/" + slot["mbox"], create=True)
      try:
        maildir.add(rcvd + data)
      except Exception as e:
        syslog.syslog(syslog.LOG_INFO, "Malformed message: %s" % str(e))
        return "501 Malformed message"
    return False

  def authenticate(self, username, password):
    slot = self.userdb.authenticate(username, password)
    if slot == None:
      return False
    self.mailbox = slot['mbox']
    return True
  
# Open debugging and logging while we still can.
debug = open("/var/log/smtpd.debug", "a")
syslog.openlog(facility=syslog.LOG_MAIL)
syslog.syslog(syslog.LOG_INFO, "initial message")

# Open the user database.
msmtp.userdb = userdb()
msmtp.debugsream = debug
minder_uent = pwd.getpwnam("minder")
minder_user = minder_uent.pw_uid

# Load the TLS certs...
tlsctx = None
try:
  tlscf = tlsconf()
  tlsctx = tlscf.tlsctx
except:
  pass

# Get the vent loop...
loop = asyncio.get_event_loop()

# Create a listener...
coroutine = loop.create_server(msmtp, "localhost", 587, family=socket.AF_INET,
                               ssl=tlsctx, backlog=5, reuse_address=True)
tlsserver = loop.run_until_complete(coroutine)

# XXX fork, close listen socket, chroot, setuid
os.chroot(mindhome)
os.setuid(minder_user)

syslog.syslog(syslog.LOG_INFO, "listening on :: port 25")

try:
  loop.run_forever()
except KeyboardInterrupt:
  pass

# Close the server
tlsserver.close()
loop.run_until_complete(tlsserver.wait_closed())
loop.close()
