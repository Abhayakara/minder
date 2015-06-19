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

ksantiRL = re.compile(r"from toccata.fugue.com.*by.*ksanti", flags = re.DOTALL + re.MULTILINE)
toccataRL1 = re.compile(r"\s*by.*toccata.fugue.com", flags = re.DOTALL)
toccataRL2 = re.compile(r".*; (.*)$", flags = re.DOTALL)

class messageObject:
  def __init__(self, key=None, timestamp=None, message=None):
    self.key = key
    self.timestamp = timestamp
    self.message = message
  def __lt__(self, other):
    if int(self.timestamp) == int(other.timestamp):
      if self.key < other.key:
        return True
    elif int(self.timestamp) < int(other.timestamp):
      return True
    return False
  def __gt__(self, other):
    if self.timestamp == other.timestamp:
      if self.key > other.key:
        return True
    elif self.timestamp > other.timestamp:
      return True
    return False
  def __eq__(self, other):
    if self.timestamp == other.timestamp:
      if self.key == other.key:
        return True
    return False
  def __le__(self, other):
    if self.timestamp == other.timestamp:
      if self.key <= other.key:
        return True
    elif self.timestamp <= other.timestamp:
      return True
    return False
  def __ge__(self, other):
    if self.timestamp == other.timestamp:
      if self.key >= other.key:
        return True
    elif self.timestamp >= other.timestamp:
      return True
    return False
  def __ne__(self, other):
    if self.timestamp != other.timestamp:
      return True
    elif self.key != other.key:
        return True
    return False
  
class aVersion:
  def __init__(self, version_id=None, timestamp=None, machines=[], messages=None):
    self.version_id = version_id
    self.timestamp = timestamp
    self.machines = machines
    self.messages = messages
  def to_line(self, num):
    if self.version_id == None:
      self.version_id = str(time.time())
    ret = str(num) + " " + self.version_id + " " + str(self.timestamp)
    if len(self.machines) > 0:
      ret = ret + " " + string.join(self.machines, " ")
    return ret
    
class headerMessageFactory(mailbox.MaildirMessage):
  def __init__(self, file):
    if sys.version_info[0] < 3:
      parser = email.parser.Parser()
    else:
      parser = email.parser.BytesParser()
    message = parser.parse(file, headersonly=True)
    if sys.version_info[0] < 3:
      return mailbox.MaildirMessage.__init__(self, message)
    else:
      return super().__init__(message)

def parse_message_date(dateString):
  if sys.version_info[0] < 3:
    # this doesn't account for the time zone, but this code is really
    # only intended to run under python 3; the reason it's working on
    # python 2 is so that I can work on it on my Chromebook, so it's
    # not the end of the world if it gets dates somewhat wrong.
    datechunks = string.split(dateString, ' ')
    dateString = string.join(datechunks[0:-2], ' ')
    return datetime.datetime.strptime(dateString, '%a, %d %b %Y %H:%M:%S')
  else:
    return email.utils.parsedate_to_datetime(dateString)

def skip_old_versions(files):
  ret = []
  for name in files:
    chunks = name.split('.')
    if len(chunks) > 1:
      if chunks[-1] not in ['old', 'older', 'oldest']:
        ret.append(name)
    else:
      ret.append(name)
  return ret

messages = None
msgSet = {}
mailboxes = {}
topics = {}

home = os.environ["HOME"]
if "MINDER_TOPIC_SOURCE" in os.environ:
  topicsDir = os.environ["MINDER_TOPIC_SOURCE"]
else:
  if not os.path.isdir(home + "/minder"):
    os.mkdir(home + "/minder", 0o700)
  if not os.path.isdir(home + "/minder/mailrat"):
    os.mkdir(home + "/minder/mailrat", 0o700)
  if not os.path.isdir(home + "/minder/mailrat/topics"):
    os.mkdir(home + "/minder/mailrat/topics", 0o700)
  topicsDir = home + "/minder/mailrat/topics"
for topic_name in skip_old_versions(os.listdir(topicsDir)):
  print("reading " + topic_name)
  f = open(topicsDir + "/" + topic_name, "r")
  
  # lines are either the beginning of a version, or else an add, or else a delete
  # The first line in a file is always the beginning of a version.   Each such
  # line contains a count--the number of adds and deletes in the version, followed
  # by a version id, followed by a timestamp, followed by a list of machines for which this version may
  # be the most recent we have shared.   Versions that aren't thought to be
  # the most recent shared with any machine can be pruned.   Fields on this line
  # are separated by spaces.  Fields must never contain spaces or newlines when
  # writing the file; this is enforced elsewhere.
  # Other lines begin with + or - and are followed by a Maildir message name,
  # and then a space, and then (for adds) the received date of the message.

  count = 0
  lineno = 0
  versions = []
  curmsgs = None
  curver = None
  everything = False

  for line in f:
    # Get rid of the trailing newline and any trailing whitespace, which shouldn't
    # be there anyway.
    line = line.rstrip()
    lineno = lineno + 1
    if line[0] == '#':
      pass
    elif count == 0:
      # Parse chunk-count version-id timestamp [machines...]
      chunks = line.split(' ')
      if len(chunks) < 3:
        raise Exception("malformed version line in " + topicsDir + "/" + topic_name + " at line " + str(lineno))
      count = int(chunks[0])
      if count < 0:
        raise Exception("negative count in " + topicsDir + "/" + topic_name + " at line " + str(lineno))
      timestamp = float(chunks[2])
      machines = chunks[3:]
      verid = chunks[1]
      if curver != None:
        if everything:
          curmsgs.sort()
          messages = copy.copy(curmsgs)
          everything = False
        # if we added messages to a copy of a previous version, they may
        # be out of order, so re-sort the list in place before copying it.
        else:
          curmsgs.sort()
        curmsgs = copy.copy(curmsgs)
        versions.append(curver)
      else:
        if topic_name == 'all':
          everything = True
        curmsgs = []
      curver = aVersion(version_id=verid, timestamp=timestamp, machines=machines, messages=curmsgs)
    elif line[0] == '+':
      chunks = line.split(' ')
      if len(chunks) != 2:
        raise Exception("malformed add line in " + topicsDir + "/" + topic_name + " at line " + str(lineno))
      msgid = chunks[0][1:]
      timestamp = float(chunks[1])
      curmsg = messageObject(key=msgid, timestamp=timestamp)
      curmsgs.append(curmsg)
      count = count - 1
      if everything and msgid not in msgSet:
        msgSet[msgid] = curmsg
    elif line[0] == '-':
      msgid = line[1:]
      found = None
      count = count - 1
      for i in range(0, len(curmsgs)):
        if curmsgs[i].key == msgid:
          curmsgs.pop(i)
          break
      else:
        raise Exception("delete for non-present message id in " + topicsDir + "/" + topic_name + " at line " + str(lineno))
    else:
      raise Exception("malformed message id line in " + topicsDir + "/" + topic_name + " at line " + str(lineno) + "at count " + str(count))
  if curver != None:
    curmsgs.sort()
    if everything:
      messages = copy.copy(curmsgs)
      everything = False
    versions.append(curver)
  if len(versions) > 0:
    topics[topic_name] = versions
  f.close()
      
if messages == None:
  messages = []
if "MINDER_MAILDIR" in os.environ:
  maildirName = os.environ["MINDER_MAILDIR"]
else:
  maildirName = home + "/mail"
maildir = mailbox.Maildir(maildirName, factory=headerMessageFactory, create=False)
keys = maildir.keys()
allNow = []
for key in keys:
  if key in msgSet:
    allNow.append(msgSet[key])
  else:
    msgDate = None
    e = None
    message = maildir.get(key)
    # Get the date from the Received: line.   The date supplied by the sender is
    # not necessarily trustworthy, particularly for spam, and can result in unread
    # mail showing up out of order in the mailbox when mail arrives in a different
    # order than the datestamps placed on the mail by the sender.
    rcvds = message.get_all("Received")
    if rcvds != None:
      if ksantiRL.match(rcvds[0]):
        tocoff = 1
      else:
        tocoff = 0
      if tocoff < len(rcvds):
        tocLines = rcvds[tocoff].split('\n')
        match = toccataRL1.match(tocLines[1])
        if match:
          match = toccataRL2.match(tocLines[2])
        if match:
          msgDate = parse_message_date(match.group(1))
    if msgDate == None:
      msgDate = parse_message_date(message.get("Date"));
    if msgDate == None:
      # If we can't find a date in the message, it's garbage.
      pass
    else:
      if sys.version_info[0] < 3:
        timestamp = (msgDate - datetime.datetime(1970, 1, 1)).total_seconds()
      else:
        timestamp = msgDate.timestamp()
      msgObj = messageObject(key=key, timestamp=timestamp, message=message)
      messages.append(msgObj)
      allNow.append(msgObj)
      msgSet[key] = msgObj
      # Make a topic or add this message to a topic based on the IMAP mailbox name
      catHeaderChunks = []
      try:
        catHeaderChunks = email.header.decode_header(message.get("X-getmail-retrieved-from-mailbox"))
      except Exception as e:
        pass
      else:
        mailboxName = ""
        for chunk in catHeaderChunks:
          mailboxName = mailboxName + codecs.decode(chunk[0], chunk[1])
        # mailboxName is essentially a network-sourced name, although in principle it
        # came from a server that we can trust, but sanitize it anyway
        
        # First translate whitespace to dashes.   We don't care a whole lot if this
        # accidentally merges two mailboxes with similar names since no mail would
        # be lost and that scenario is quite unlikely.
        mbnChunks = mailboxName.split()
        mailboxName = '-'.join(mbnChunks)
        
        # Now anything else gets percent-encoded.
        mailboxName = urllib.parse.quote(mailboxName, '')
        
        if mailboxName not in mailboxes:
          mailboxes[mailboxName] = []
        mailboxArray = mailboxes[mailboxName]
        mailboxArray.append(msgObj)

# Sort the new message list and add a version to the "all" set.
# Note that if there is an IMAP maibox called "all", this obliterates
# it.   Tough luck.   Those messages are still the in "all" topic.   :)
allNow.sort()
mailboxes['all'] = allNow

for mailboxName in mailboxes.keys():
  print(mailboxName + ": " + str(len(mailboxes[mailboxName])))
  mailboxes[mailboxName].sort()
  newversion = aVersion(timestamp=time.time(), messages=mailboxes[mailboxName])
  if mailboxName in topics:
    topics[mailboxName].append(newversion)
  else:
    topics[mailboxName] = [newversion]

# Now write out all the topics.

# if we are testing, we'll get a destination into which to write the
# results
if "MINDER_TOPIC_DEST" in os.environ:
  topicsDir = os.environ["MINDER_TOPIC_DEST"]
# otherwise the new stuff goes where the old stuff was.
for key, topic in topics.items():
  topfile_name = topicsDir + "/" + key
  topfile = open(topfile_name + ".new", "w")
  prev = []
  for version in topic:
    msgs = version.messages
    old = 0
    cur = 0
    output = []
    # to diff two lists of messages, we make the following critical assumptions:
    #  1. the message arrival time for a particular key is the same
    #  2. the lists are sorted according to message arrival time
    # practically speaking, if a message key appears twice with different
    # arrival times, the list will contain that key twice.   It may be
    # that we should have special code that detects this when combing
    # the lists, but the easiest way to detect it is when adding.
    # XXX think about this
    #output.append("prev: " + str(len(prev)))
    for item in prev:
      #output.append("#pre: " + item.key + " " + str(item.timestamp))
      pass
    #output.append("msgs: " + str(len(msgs)))
    for item in msgs:
      #output.append("#msg: " + item.key + " " + str(item.timestamp))
      pass
    while old < len(prev) or cur < len(msgs):
      if old < len(prev) and cur < len(msgs):
        # I'm thinking the right way to deal with duplicate keys with different
        # timestamps is to make a list sorted by keys and search for duplicates
        # after creating the list, either by reading it from a file or by
        # scanning the messages.   For now we treat messages with identical key
        # that do not appear in order as if they are different messages.
        if prev[old].key == msgs[cur].key:
          #output.append("#skip:")
          #output.append("#prev[" + str(old) + "] = " + prev[old].key + " " + str(prev[old].timestamp))
          #output.append("#msgs[" + str(cur) + "] = " + msgs[cur].key + " " + str(msgs[cur].timestamp))
          old = old + 1
          cur = cur + 1
        # If the timestamp in prev is greater than in cur,
        # it means that the item in prev isn't present in
        # cur.
        elif prev[old].timestamp > msgs[cur].timestamp:
          #output.append("#add:")
          #output.append("#prev[" + str(old) + "] = " + prev[old].key + " " + str(prev[old].timestamp))
          #output.append("#msgs[" + str(cur) + "] = " + msgs[cur].key + " " + str(msgs[cur].timestamp))
          output.append("+" + msgs[cur].key + " " + str(msgs[cur].timestamp))
          cur = cur + 1
        # Otherwise this item was present in cur but not in prev
        else:
          #output.append("#del:")
          #output.append("#prev[" + str(old) + "] = " + prev[old].key + " " + str(prev[old].timestamp))
          #output.append("#msgs[" + str(cur) + "] = " + msgs[cur].key + " " + str(msgs[cur].timestamp))
          output.append("-" + prev[old].key)
          old = old + 1
      # We have exhausted the contents of the previous version, so this
      # must be an entry that exists only in the current version
      elif old == len(prev):
        #output.append("#otheradd:")
        #output.append("#prev[" + str(old) + "] = Null (limit " + str(len(prev)) + ")")
        #output.append("#msgs[" + str(cur) + "] = " + msgs[cur].key + " " + str(msgs[cur].timestamp))
        output.append("+" + msgs[cur].key + " " + str(msgs[cur].timestamp))
        cur = cur + 1
      else:
        #output.append("#otherdel:")
        #output.append("#prev[" + str(old) + "] = " + prev[old].key + " " + str(prev[old].timestamp))
        #output.append("#msgs[" + str(cur) + "] = Null (limit " + str(len(msgs)) + ")")
        output.append("-" + prev[old].key)
        old = old + 1
    topfile.write(version.to_line(len(output)) + "\n")
    for entry in output:
      topfile.write(entry + "\n")
    prev = msgs
  topfile.close()
  # For paranoia at the moment we're keeping a few revisions.   This
  # could almost certainly be done more elegantly, and it would be nice
  # to do versioning in subdirectories.
  try:
    os.unlink(topfile_name + ".older")
  except FileNotFoundError as e:
    pass
  try:
    os.link(topfile_name + ".old", topfile_name + ".older")
  except FileNotFoundError as e:
    pass
  else:
    os.unlink(topfile_name + ".old")
  try:
    os.link(topfile_name, topfile_name + ".old")
  except FileNotFoundError as e:
    pass
  else:
    os.unlink(topfile_name)
  os.link(topfile_name + ".new", topfile_name)
  os.unlink(topfile_name + ".new")

exit(0)
