#!/usr/bin/env python3

import mailbox
import email
import email.parser
import email.utils
import email.header
import operator
import re
import os
import os.path
import sys
path = sys.path
dnslib = os.path.normpath(sys.path[0] + "/../maildns")
sys.path.append(dnslib)
import copy
import codecs
import time
import datetime
import string
import urllib.parse
import spf
import asyncio
import dns.resolver
import dns.rdtypes.ANY.MX
import dns.rdtypes.ANY.TXT
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.name
import curses

# Things to look at:
# - Negatives
#   - matching gecos, different email address
#   - matching subject line, different email address
#   - words in subject line with punctuation or numbers in
#   - no MX record
#   - only one A record
#   - no AAAA record
#   - non-standard TLD (not org, com, net, ccTLD)
#   - IP address
#   - can't connect twice.
#   - new IP address, new sender
#   - body of text contains URLs with lots of noise
#   - body of text contains URLs that are masked
#   - 
# - Positives
#   - sender email address appears in outbox AND
#   - sender SPF checks out
#   - DKIM checks out
#   - same IP address that generally checks out delivers
#     email from the same sender multiple times over a
#     long interval
#
# Maintain a whitelist of hosts that have been vetted and from
# which legit mail has been accepted
#
# Maintain a blacklist of hosts from which spam (not merely
# junk) has been received

# Initial objectives:
#  suck in whitelist
#  suck in inbox
#  use whitelist and inbox to promote mail to the top
#

# These are the lines we expect the minder smtp daemon to put at the beginning
# of every email message received.   Either it is from an IPv6 address or
# from an IPv4 address, so one of these two will match.   We try the more
# specific one first, of course.
ipv4RL = re.compile(r"from ::ffff:(\d+.\d+.\d+.\d+); (.*)$", flags = re.DOTALL)
ipv6RL = re.compile(r"from ([:a-f0-9]*); (.*)$", flags = re.DOTALL)

running_domains = False
if len(sys.argv) > 1:
  running_domains = True

# XXX
sourceMaildir = "/etc/minder/mailboxes/plemon"
destMaildir = "/etc/minder/dovecot/plemon"
whitelistFile = "/etc/minder/plemon.whitelist"
blacklistFile = "/etc/minder/plemon.blacklist"
dipFile = "/etc/minder/dip.whitelist"

class messageReferent:
  def __init__(self, key, message, source_addr,
               sender_name, sender_addr, sender_domain,
               recipients, subject, list, bogus):
    self.key = key
    self.message = message
    self.source_addr = source_addr
    self.sender_name = sender_name
    self.sender_addr = sender_addr
    self.sender_domain = sender_domain
    self.recipients = recipients
    self.subject = subject
    self.bogus = bogus
    self.list = list

inbox = mailbox.Maildir(destMaildir, create=False)
haystack = mailbox.Maildir(sourceMaildir, create=False)

def processDir(maildir, every, processMessage):
  keys = maildir.keys()
  for key in keys:
    message = maildir.get(key)
    if every or message.get_subdir() == "new":
      bogus = False
      rcvds = message.get_all("Received")
      source_addr = None
      if rcvds != None:
        match = ipv4RL.match(rcvds[0])
        if match:
          source_addr = match.group(1)
        else:
          match = ipv6RL.match(rcvds[0])
          if match:
            source_addr = match.group(1)
      # Messages should only have one sender.   I think it's a red flag
      # if a message doesn't say who it's from, or reports more than one
      # sender, but for now we just try to extract the sender if we
      # can.
      sender_name = None
      sender_addr = None
      sender_domain = None
      list = None
      sender = None
      ml = message.get_all("List-Id")
      if ml != None:
        if len(ml) == 1:
          list = ml[0]
          list_name, list_addr = email.utils.parseaddr(list)
          bits = list_addr.split(".")
          if len(bits) > 1:
            lhs = bits[0]
            rhs = ".".join(bits[1:])
            sender_domain = rhs
            sender_name = list_name
            sender_addr = lhs + "@" + rhs
            sender_addr = sender_addr.lower()
            sender = list
      if sender == None:
        froms = message.get_all("From")
        if froms != None and len(froms) > 0:
          sender = froms[0]
          sender_name, sender_addr = email.utils.parseaddr(sender)
          sender_addr = sender_addr.lower()
          segments = sender_addr.split("@")
          if len(segments) != 2:
            # bogus sender...
            bogus = True
          else:
            sender_domain = segments[1]
      # Recipients...
      tos = message.get_all("To")
      recipients = []
      if tos != None and len(tos) > 0:
        recipients = email.utils.getaddresses(tos)
      # There really should only be one subject.
      subjs = message.get_all("Subject")
      subject = None
      if subjs:
        if len(subjs) == 1:
          subject = subjs[0]
        elif len(subjs) > 0:
          bogus = True
      else:
        bogus = True
      ref = messageReferent(key, message, source_addr,
                            sender_name, sender_addr, sender_domain,
                            recipients, subject, list, bogus)
      processMessage(ref, source_addr, sender_name, sender_addr, sender_domain,
                     recipients, subject, bogus)
      
whitelist = []
blacklist = []
domain_ip_whitelist = {}
inboxSenders = {}
goodSrcAddrs = {}
senderSrcAddrs = {}
domainSrcAddrs = {}
goodDomains = {}

# Read the whitelist.
wf = open(whitelistFile, "r")
for line in wf:
  line = line.rstrip().lower()
  name, addr = email.utils.parseaddr(line)
  whitelist.append(addr)
wf.close()

# Read the blacklist
wf = open(blacklistFile, "r")
for line in wf:
  line = line.rstrip().lower()
  name, addr = email.utils.parseaddr(line)
  blacklist.append(addr)
wf.close()

# read the domain/ip whitelist
df = open(dipFile, "r")
for line in df:
  line = line.rstrip()
  hunks = line.split(" ")
  ipaddr = hunks[1]
  domain = hunks[0]
  if ipaddr in domain_ip_whitelist:
    domain_ip_whitelist[ipaddr].append(domain)
  else:
    domain_ip_whitelist[ipaddr] = [domain]

# Read the inbox
def inboxMessage(ref, srcaddr, sname, saddr, domain, recips, subj, bogus):
  # We don't need to consider bogus messages here (I think!)
  if bogus:
    return
  if srcaddr != None:
    if srcaddr not in goodSrcAddrs:
      goodSrcAddrs[srcaddr] = True
    if saddr != None:
      if saddr in senderSrcAddrs:
        if srcaddr not in senderSrcAddrs[saddr]:
          senderSrcAddrs[saddr].append(srcaddr)
      else:
        senderSrcAddrs[saddr] = [srcaddr]
    if domain != None:
      if domain in domainSrcAddrs:
        if srcaddr not in domainSrcAddrs[domain]:
          domainSrcAddrs[domain].append(srcaddr)
      else:
        domainSrcAddrs[domain] = [srcaddr]
  if domain != None and domain not in goodDomains:
    goodDomains[domain] = True
  if saddr != None and saddr not in inboxSenders:
    inboxSenders[saddr] = True
processDir(inbox, True, inboxMessage)

filterSenders = {}
filterIPAddrs = {}
filterDomains = {}
filterNames = {}
multiSenderNames = {}
multiNameSenders = {}
bogusMessages = []
badSrcAddrs = {}
filterDomainSenders = {}
filterDomainMessages = {}

loop = asyncio.get_event_loop()

# Read the filter folder
def haystackMessage(ref, srcaddr, sname, saddr, domain, recips, subj, bogus):
  # Can't make much out of a bogus message?
  if bogus:
    bogusMessages.append(ref)
    return
  labels = domain.split(".")
  tld = labels[-1]
  # Don't even bother with weird TLDs.
  if len(tld) != 2 and tld not in ["org", "com", "net", "info"]:
    return
  if saddr != None:
    if saddr in filterSenders:
      filterSenders[saddr].append(ref)
    else:
      filterSenders[saddr] = [ref]
    if sname != None:
      if saddr in multiNameSenders:
        thunk = multiNameSenders[saddr]
        if sname in thunk:
          thunk[sname].append(ref)
        else:
          thunk[sname] = [ref]
      else:
        multiNameSenders[saddr] = { sname: [ref] }
      if sname in multiSenderNames:
        thunk = multiSenderNames[sname]
        if saddr in thunk:
          thunk[saddr].append(ref)
        else:
          thunk[saddr] = [ref]
      else:
        multiSenderNames[sname] = { saddr: [ref] }
  if srcaddr != None:
    if srcaddr in filterIPAddrs:
      filterIPAddrs[srcaddr].append(ref)
    else:
      filterIPAddrs[srcaddr] = [ref]
  if domain != None:
    if domain in filterDomains:
      filterDomains[domain].append(ref)
    else:
      filterDomains[domain] = [ref]
    if saddr != None:
      if domain in filterDomainSenders:
        if saddr not in filterDomainSenders[domain]:
          filterDomainSenders[domain].append(saddr)
      else:
        filterDomainSenders[domain] = [saddr]
processDir(haystack, False, haystackMessage)

# delete the entries in multiNameSenders and multiSenderNames that do not represent
# actual duplication:

dels = []
for name in multiNameSenders.keys():
  if len(multiNameSenders[name]) == 1:
    dels.append(name)
for name in dels:
  del multiNameSenders[name]

dels = []
for sender in multiSenderNames.keys():
  if len(multiSenderNames[sender]) == 1:
    dels.append(sender)
for name in dels:
  del multiSenderNames[name]

consumedSenders = {}
print("Whitelist:")
for addr in whitelist:
  if addr in filterSenders:
    print("  From:", addr)
    for ref in filterSenders[addr]:
      message = ref.message
      print("   ", message.get("Subject"))
      if ref.source_addr != None and ref.sender_domain != None:
        result = None
        if ref.source_addr in domain_ip_whitelist:
          if ref.sender_domain in domain_ip_whitelist[ref.source_addr]:
            result = "pass"
        if result == None:
          # The whitelist can only work for senders that support SPF, and then only
          # if the source address passes the SPF check; otherwise you could bypass
          # the spam filter by faking a From: header
          task = asyncio.async(spf.check_host(ref.source_addr,
                                              ref.sender_domain, addr))
          loop.run_until_complete(task)
          result = task.result()
          if result == "pass":
            if ref.source_addr in domain_ip_whitelist:
              domain_ip_whitelist[ref.source_addr].append(ref.sender_domain)
        if result == "pass":
          if os.getuid() == 0:
            inbox.add(message)
            haystack.remove(ref.key)
        else:
          print("faked whitelist sender", addr, ref.source_addr)
      else:
        print("badwl: sender =", addr, "addr =",
              ref.source_addr, "dom = ", ref.sender_domain)
    consumedSenders[addr] = filterSenders[addr]
    del filterSenders[addr]

print("Inbox:")
for addr in inboxSenders:
  if addr in filterSenders and addr not in whitelist:
    print("  From:", addr)
    for ref in filterSenders[addr]:
      print("   ", ref.message.get("Subject"))
    consumedSenders[addr] = filterSenders[addr]
    del filterSenders[addr]

print("goodDomain:")
senders = []
for domain in filterDomains:
  if domain in goodDomains:
    if domain in domainSrcAddrs:
      srcAddrs = domainSrcAddrs[domain]
      for ref in filterDomains[domain]:
        if ref.source_addr in srcAddrs:
          if ref.sender_addr not in senders:
            senders.append(ref.sender_addr)
for sender in senders:
  if sender in multiNameSenders:
    names = multiNameSenders[sender]
    for name in names:
      print("From:", name, "<" + sender + ">")
      refs = names[name]
      for ref in refs:
        print("  ", ref.message.get("Subject"))
        print("  ", ref.source_addr)
  else:
    print(sender)

iffyDomains = []
for name in multiSenderNames:
  senders = multiSenderNames[name]
  for sender in senders:
    refs = senders[sender]
    for ref in refs:
      if ref.sender_domain not in goodDomains and ref.sender_domain not in iffyDomains:
        iffyDomains.append(ref.sender_domain)

resolver = dns.resolver.Resolver()
resolver.use_edns(0, 0, 1410)

@asyncio.coroutine
def check_domain(domain):
  try:
    result = yield from resolver.aquery(domain, "txt", raise_on_no_answer=True)
  except:
    return None
  return domain

@asyncio.coroutine
def wait_for_answers(loop):
  tasks = []
  for domain in filterDomains:
    if domain not in iffyDomains:
      tasks.append(check_domain(domain))
      if len(tasks) > 30:
        done, pending = yield from asyncio.wait(tasks, timeout=5)
        for task in done:
          domain = task.result()
          if domain != None:
            print(domain, len(filterDomainSenders[domain]), len(filterDomains[domain]))
        for task in pending:
          task.cancel()
        tasks = []
  loop.stop()

def main(win):
  df = open(sys.argv[1], "r")
  for line in df:
    line.rstrip()
    hunks = line.split(" ")
    if len(hunks) > 0:
      if hunks[0] == "b":
        for sender in filterDomainSenders[hunks[1]]:
          blacklist.append(sender)
      elif hunks[0] == "l":
        for sender in filterDomainSenders[hunks[1]]:
          for ref in filterSenders[sender]:
            # For a particular sender to be a whitelist candidate, we should have
            # at least one message from that sender that generates a "pass" from SPF.
            if ref.source_addr != None:
              task = asyncio.async(spf.check_host(ref.source_addr, hunks[1], sender))
              loop.run_until_complete(task)
              result = task.result()
              if result == "pass":
                message = haystack.get(ref.key)
                win.clear()
                win.addstr(0, 0, "From: " + ref.sender_name + "<" + sender + ">")
                subj = message.get("subject")
                if subj == None:
                  subj = ""
                win.addstr(1, 0, "Subject:" + subj)
                payload = message.get_payload()
                # If it's not a string, it's multipart, so look for a candidate we
                # can display.
                if not isinstance(payload, str):
                  if (len(payload) == 1 and
                      payload[0].get_content_type == "multipart/alternative"):
                    payload = payload[0].get_payload()
                  candidate = None
                  for instance in payload:
                    # Prefer text/plain
                    if instance.get_content_maintype() == "text":
                      if instance.get_content_maintype() == "plain":
                        candidate = instance
                        break
                      else:
                        if candidate == None:
                          candidate = instance
                  if candidate == None:
                    sep = " "
                    msg = "No viable candidate to display.   Types are:"
                    for instance in payload:
                      msg = msg + sep + instance.get_content_type()
                      sep = ", "
                    payload = msg
                  else:
                    payload = candidate.get_payload()
                (height, width) = win.getmaxyx()
                offset = 0
                for curline in range(3, height - 1):
                  nxt = payload.find("\n", offset)
                  if nxt == -1:
                    nxt = len(payload)
                  linelen = nxt - offset
                  if linelen > 0:
                    if payload[linelen - 1] == '\r':
                      linelen = linelen - 1
                  if linelen > width:
                    linelen = width
                  win.addstr(curline, 0, payload[offset:offset + linelen])
                  offset = nxt + 1
                  if offset > len(payload):
                    offset = len(payload)
                win.refresh()
                c = win.getch()
                break


if not running_domains:
  print("starting TXT checks...")
  loop = asyncio.get_event_loop()
  co = wait_for_answers(loop)
  loop.run_until_complete(co)
else:
  curses.wrapper(main)
