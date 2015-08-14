#!/usr/bin/env python3

import smtps.smtp as smtp
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
      return False
    if address[0] not in self.users:
      return False
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
        return False
    else:
      udata = udmap[address[1]]
    hash = base64.standard_b64decode(udata["pass"])
    salt = hash[32:]
    sha = hashlib.sha256()
    sha.update(password)
    sha.update(salt)
    chash = sha.digest()
    if chash == hash[:32]:
      return True
    return False

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

class msmtp(smtp.SMTPServer):
  userdb = None

  def validate_rcptto(self, address):
    udbaddr = self.userdb.parse_address(address)
    if udbaddr == None:
      self.push("501 Syntax: RCPT TO: <address>")
      syslog.syslog(syslog.LOG_INFO, "501 Syntax: RCPT TO: %s" % address)
      return False
    
    if not self.userdb.validate_domain(udbaddr):
      self.push('551 Not a local domain, relaying not available.')
      syslog.syslog(syslog.LOG_INFO,
		    "551 Invalid domain: RCPT TO: %s" % address)
      return False

    if not self.userdb.validate_address(udbaddr):
      self.push("550 Mailbox unavailable.")
      syslog.syslog(syslog.LOG_INFO,
		    "550 Invalid mailbox: RCPT TO: %s" % address)
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
    return self.userdb.authenticate(username, password)
  
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
tlscf = tlsconf()

# Get the vent loop...
loop = asyncio.get_event_loop()

# Create a listener...
coroutine = loop.create_server(msmtp, "localhost", 465, family=socket.AF_INET,
                               ssl=tlscf.tlsctx, backlog=5, reuse_address=True)
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
