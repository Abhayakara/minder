#!/usr/bin/env python

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

ksantiRL = re.compile(r"from toccata.fugue.com.*by.*ksanti", flags = re.DOTALL + re.MULTILINE)
toccataRL1 = re.compile(r"\s*by.*toccata.fugue.com", flags = re.DOTALL)
toccataRL2 = re.compile(r".*; (.*)$", flags = re.DOTALL)

class messageObject:
  def __init__(self, key=None, timestamp=None, message=None):
    self.key = key
    self.timestamp = timestamp
    self.message = message

class aVersion:
  def __init__(self, version_id=None, timestamp=None, machines=None, messages=None):
    self.version_id = version_id
    self.timestemp = timestamp
    self.machines = machines
    self.curmsgs = curmsgs
    
class headerMessageFactory(mailbox.MaildirMessage):
  def __init__(self, file):
    parser = email.parser.BytesParser()
    message = parser.parse(file, headersonly=True)
    return super().__init__(message)

messages = None
msgSet = set()
mailboxes = {}
topics = {}

home = os.environ["HOME"]

if not os.path.isdir(home + "/minder"):
  os.mkdir(home + "/minder", 0o700)
if not os.path.isdir(home + "/minder/mailrat"):
  os.mkdir(home + "/minder/mailrat", 0o700)
if not os.path.isdir(home + "/minder/mailrat/topics"):
  os.mkdir(home + "/minder/mailrat/topics", 0o700)
for topic_name in os.listdir(home + "/minder/mailrat/topics"):
  f = open(home + "/minder/mailrat/topics/" + topic_name, "r")
  
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
    line.rstrip()
    lineno = lineno + 1
    if count == 0:
      # Parse chunk-count version-id timestamp [machines...]
      chunks = line.split(' ')
      if len(chunks) < 3:
        raise Exception("malformed version line in ~/minder/mailrat/topics/" + topic_name + " at line " + str(lineno))
      count = int(chunks[0])
      if count < 0:
        raise Exception("negative count in ~/minder/mailrat/topics/" + topic_name + " at line " + str(lineno))
      timestamp = int(chunks[2])
      machines = chunks[3:]
      verid = chunks[1]
      if curver != None:
        if everything:
          messages = copy.copy(curmsgs)
          everything = False
        # if we added messages to a copy of a previous version, they may
        # be out of order, so re-sort the list in place before copying it.
        else:
          curmsgs.sort(lambda foo: foo.timestamp)
        curmsgs = copy.copy(curmsgs)
        versions.append(curver)
      else:
        if topic == 'all':
          everything = True
        curmsgs = []
      curver = aVersion(version_id=verid, timestamp=timestamp, machines=machines, messages=curmsgs)
    elif line[0] == '+':
      chunks = line.split(' ')
      if len(chunks) != 2:
        raise Exception("malformed add line in ~/minder/mailrat/topics/" + topic_name + " at line " + str(lineno))
      msgid = chunks[0][1:]
      timestamp = int(chunks[1])
      curmsg = messageObject(key=msgid, timestamp=timestamp)
      curmsgs.append(curmsg)
      count = count - 1
      if everything:
        msgSet.add(msgid)
    elif line[0] == '-':
      msgid = line[1:]
      found = None
      for i in range(0, len(curmsgs)):
        if curmsgs[i].key == msgid:
          curmsgs.pop(i)
          break
      else:
        raise Exception("delete for non-present message id in ~/minder/mailrat/topics/" + topic_name + " at line " + str(lineno))
    else:
      raise Exception("malformed message id line in ~/minder/mailrat/topics/" + topic_name + " at line " + str(lineno))
  if curver != None:
    if everything:
      messages = copy.copy(curmsgs)
      everything = False
    versions.append(curver)
  if len(versions) > 0:
    topics['topic'] = versions
  f.close()
      
if messages == None:
  messages = []
maildir = mailbox.Maildir("~/mail", factory=headerMessageFactory, create=False)
keys = maildir.keys()
for key in keys:
  if key not in msgSet:
    message = maildir.get(key)
    msgDate = None
    try:
      msgDate = email.utils.parsedate_to_datetime(message.get("Date"));
    except Exception as e:
      pass
    if msgDate == None:
      try:
        rcvds = message.get_all("Received")
        try:
          if ksantiRL.match(rcvds[0]):
            tocoff = 1
          else:
            tocoff = 0
          tocLines = rcvds[tocoff].split('\n')
          match = toccataRL1.match(tocLines[1])
          if match:
            match = toccataRL2.match(tocLines[2])
            if match:
              msgDate = email.utils.parsedate_to_datetime(match.group(1))
        except Exception as f:
          pass
      except Exception as f:
          pass
    if msgDate == None:
      try:
        print("From: " + message.get("From") + " :: " + str(e))
      except Exception as f:
        print("key0: " + key + ": " + str(e))
    else:
      msgObj = messageObject(key=key, timestamp=msgDate.timestamp(), message=message)
      messages.append(msgObj)
      msgSet.add(key)
      # Make a topic or add this message to a topic based on the IMAP mailbox name
      catHeaderChunks = []
      try:
        catHeaderChunks = email.header.decode_header(message.get("X-getmail-retrieved-from-mailbox"))
      except Exception as e:
        pass
      else:
        mailbox = ""
        for chunk in catHeaderChunks:
          mailbox = mailbox + codecs.decode(chunk[0], chunk[1])
        if mailbox not in mailboxes:
          if mailbox in topics:
            mailboxes[mailbox] = copy.copy(topics[category][0].messages)
          else:
            mailboxes[mailbox] = []
        mailbox = mailboxes[mailbox]
        mailbox.append(msgObj)

# Sort the new message list and add a version to the "all" set.
# Note that if there is an IMAP maibox called "all", this obliterates
# it.   Tough luck.   Those messages are still the in "all" topic.   :)
messages.sort(key=lambda foo: foo.timestamp)
mailboxes['all'] = messages

for mailbox in mailboxes.keys():
  print(mailbox + ": " + str(len(mailboxes[mailbox])))
  mailboxes[mailbox].sort(key=lambda foo: foo.timestamp)
  newversion = aVersion(timestamp=time.time(), messages=mailboxes[mailbox])
  if mailbox in topics:
    topics[mailbox] = [newversion] + topics[mailbox]
  else:
    topics[mailbox] = [newversion]

# Now write out all the topics.
for key, topic in topics.items():
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
    while old < len(prev) or cur < len(msgs):
      if old < len(prev) and cur < len(msgs):
        # I'm thinking the right way to deal with duplicate keys with different
        # timestamps is to make a list sorted by keys and search for duplicates
        # after creating the list, either by reading it from a file or by
        # scanning the messages.   For now we treat messages with different key
        # but identical timestamp as if they are different messages.
        if (prev[old].key == cur[old].key and
            prev[old].timestamp == cur[old].timestamp):
          old = old + 1
          new = new + 1
        # If the timestamp in prev is greater than in cur,
        # it means that the item in prev isn't present in
        # cur.
        elif prev[old].timestamp > cur[old].timestamp:
          output.append("-" + prev[old].key)
          old = old + 1
        # Otherwise this item was present in cur but not in prev
        else:
          output.append("+" + cur[new].key + " " + str(cur[new].timestamp))
          new = new + 1
      # We have exhausted the contents of the previous version, so this
      # must be an entry that exists only in the current version
      elif old == len(prev):
        output.append("+" + cur[new].key + " " + str(cur[new].timestamp))
        new = new + 1
      else:
        output.append("-" + prev[old].key)
    topfile.write(

exit(0)
