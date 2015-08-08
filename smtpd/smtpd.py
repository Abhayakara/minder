#!/usr/bin/env python3

import smtps.smtpd as smtpd
import asyncore
import sys
import pdb
import os
import pwd
import socket

import mailbox
import email
import email.parser
import email.utils
import email.header

import syslog

mindhome = "/etc/minder"

class userdb:
  users = {}
  domains = []
  wildcard_domains = []

  def __init__(self):
    uf = open(mindhome + "/userdb", "r")
    for line in uf:
      line = line.rstrip()
      # user:mailbox:password:domains...
      fields = line.split(":")
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
    uf.close()

  def parse_address(self, address):
    # Python's parseaddr function doesn't actually do the right thing
    # here, so for now this is going to be a very manual process,
    # more's the pity.
    parts = address.split("@")
    if len(parts) != 2:
      return None
    user = parts[0]
    domain = parts[1]
    return [user, domain]

  def find_wildcard(self, subdomain, domains):
      splode = subdomain.split(".")
      for i in range(0, len(splode)):
        wildsub = "*." + ".".join(splode[i:])
        print("trying: ", wildsub)
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

class msmtp_channel(smtpd.SMTPChannel):
  userdb = None

  def __init__(self, server, conn, addr, data_limit, _map, userdb):
    self.userdb = userdb
    return super().__init__(server, conn, addr, data_limit, _map)

  def validate_rcptto(self, address):
    udbaddr = self.userdb.parse_address(address)
    if udbaddr == None:
      self.push("501 Syntax: RCPT TO: <address>")
      print("501 Syntax: RCPT TO: <address>")
      return False
    
    if not self.userdb.validate_domain(udbaddr):
      print('551 Not a local domain, relaying not available.')
      self.push('551 Not a local domain, relaying not available.')
      return False

    if not self.userdb.validate_address(udbaddr):
      print("550 Mailbox unavailable.")
      self.push("550 Mailbox unavailable.")
      return False

    return True

class msmtpd(smtpd.SMTPServer):
  userdb = None
  minder_user = None
  debugstream = None

  def __init__(self, localaddr, debugstream=None):
    self.userdb = userdb()
    minder_uent = pwd.getpwnam("minder")
    self.minder_user = minder_uent.pw_uid

    if debugstream == None:
      foo = super().__init__(localaddr, None, channel_class=msmtp_channel)
    else:
      self.debugstream = debugstream
      foo = super().__init__(localaddr, None, channel_class=msmtp_channel,
                             debugstream=debugstream)

    # XXX fork, close listen socket, chroot, setuid
    os.chroot(mindhome)
    os.setuid(self.minder_user)

    syslog.syslog(syslog.LOG_INFO, "listening on :: port 25")

    return foo

  def handle_accepted(self, conn, addr):
    syslog.syslog(syslog.LOG_INFO, "Connect from %s" % addr[0])
    channel = msmtp_channel(self, conn, addr, self.data_size_limit, self._map,
                            self.userdb)

  def process_message(self, peer, mailfrom, rcpttos, data):
    syslog.syslog(syslog.LOG_INFO, "Mail from %s via %s" % (mailfrom, peer[0]))
    boxes = {}
    self.debugstream.flush()
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
      rcvd = "Received: from %s; %s\r\n" % (peer[0], email.utils.formatdate())
      #parser = email.parser.Parser()
      #message = parser.parsestr(data)
      maildir.add(rcvd + data)

def run():
  debug = open("/var/log/smtpd.debug", "a")
  syslog.openlog(facility=syslog.LOG_MAIL)
  syslog.syslog(syslog.LOG_INFO, "initial message")
  
  foo = msmtpd(('::', 25), debugstream=debug)
  try:
    asyncore.loop()
  except KeyboardInterrupt:
    pass

if __name__ == '__main__':
  run()
