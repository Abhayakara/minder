#!/usr/bin/env python3

import mailbox
import email
import email.parser
import email.utils
import email.header
import operator
import re
import os
import sys
import copy
import codecs
import time
import datetime
import string
import urllib.parse

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
ipv6RL = re.compile(r"from ([^;]*); (.*)$", flags = re.DOTALL)

# XXX
sourceMaildir = "/etc/minder/mailboxes/plemon"
destMaildir = "/etc/minder/dovecot/plemon"
whitelistFile = "/etc/minder/plemon.whitelist"

class messageReferent:
  def __init__(self, key, message, source_addr,
               sender_name, sender_addr, sender_domain,
               recipients, subject, bogus):
    self.key = key
    self.message = message
    self.source_addr = source_addr
    self.sender_name = sender_name
    self.sender_addr = sender_addr
    self.sender_domain = sender_domain
    self.recipients = recipients
    self.subject = subject
    self.bogus = bogus

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
          source_addr = (match.group(1), '4')
        else:
          match = ipv6RL.match(rcvds[0])
          if match:
            source_addr = (match.group(1), '6')
          else:
            print("no match:", rcvds[0])
      # Messages should only have one sender.   I think it's a red flag
      # if a message doesn't say who it's from, or reports more than one
      # sender, but for now we just try to extract the sender if we
      # can.
      sender_name = None
      sender_addr = None
      sender_domain = None
      froms = message.get_all("From")
      if len(froms) > 0:
        sender = froms[0]
        sender_name, sender_addr = email.utils.parseaddr(sender)
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
                            recipients, subject, bogus)
      processMessage(ref, source_addr, sender_name, sender_addr, sender_domain,
                     recipients, subject, bogus)
      
whitelist = []
inboxSenders = {}
goodSrcAddrs = {}
senderSrcAddrs = {}
domainSrcAddrs = {}
goodDomains = {}

# Read the whitelist.
wf = open(whitelistFile, "r")
for line in wf:
  line.rstrip()
  name, addr = email.utils.parseaddr(line)
  whitelist.append(addr)
wf.close()

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

# Read the filter folder
def haystackMessage(ref, srcaddr, sname, saddr, domain, recips, subj, bogus):
  # Can't make much out of a bogus message?
  if bogus:
    bogusMessages.append(ref)
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
      inbox.add(message)
      haystack.remove(ref.key)
    consumedSenders[addr] = filterSenders[addr]
    del filterSenders[addr]

print("Inbox:")
for addr in inboxSenders:
  if addr in filterSenders and addr not in whitelist:
    print("  From:", addr)
    for message in filterSenders[addr]:
      print("   ", message.get("Subject"))
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
  print(sender)
