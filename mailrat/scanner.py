#!/usr/bin/env python3

import mailbox
import email
import email.parser
import email.utils
import operator
import re
import os
import sys
import copy

ksantiRL = re.compile(r"from toccata.fugue.com.*by.*ksanti", flags = re.DOTALL + re.MULTILINE)
toccataRL1 = re.compile(r"\s*by.*toccata.fugue.com", flags = re.DOTALL)
toccataRL2 = re.compile(r".*; (.*)$", flags = re.DOTALL)

class headerMessageFactory(mailbox.MaildirMessage):
  def __init__(self, file):
    parser = email.parser.BytesParser()
    message = parser.parse(file, headersonly=True)
    return super().__init__(message)

messages = {}

if not os.path.isdir("~/minder"):
  os.mkdir("~/minder", 0700)
if not os.path.isdir("~/minder/mailrat"):
  os.mkdir("~/minder/mailrat", 0700)
if not os.path.isdir("~/minder/mailrat/topics"):
  os.mkdir("~/minder/mailrat/topics", 0700)
for topic_name in os.listdir("~/minder/mailrat/topics"):
  f = open("~/minder/mailrat/topics/" + topic_name, "r")
  
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
        # if we added messages to a copy of a previous version, they may
        # be out of order, so re-sort the list in place before copying it.
        curmsgs.sort(lambda foo: foo[1])
        curmsgs = copy.copy(curmsgs)
        versions.append(curver)
      else:
        curmsgs = []
      curver = (verid, timestamp, machines, curmsgs)
    else if line[0] == '+':
      chunks = line.split(' ')
      if len(chunks) != 2:
        raise Exception("malformed add line in ~/minder/mailrat/topics/" + topic_name + " at line " + str(lineno))
      msgid = chunks[0][1:]
      timestamp = int(chunks[1])
      curmsg = (msgid, timestamp)
      curmsgs.append(curmsg)
      count = count - 1
    else if line[0] == '-':
      msgid = line[1:]
      found = None
      for i in range(0, len(curmsgs)):
        if curmsgs[i][0] == msgid:
          curmsgs.pop(i)
          break
      else:
        raise Exception("delete for non-present message id in ~/minder/mailrat/topics/" + topic_name + " at line " + str(lineno))
    else:
      raise Exception("malformed message id line in ~/minder/mailrat/topics/" + topic_name + " at line " + str(lineno))
  if curver != None:
    versions.append(curver)
  if len(versions) > 0:
    topics['topic'] = versions
  f.close()
      
maildir = mailbox.Maildir("~/mail", factory=headerMessageFactory, create=False)
keys = maildir.keys()
messages = []
for key in keys:
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
    messages.append((msgDate.timestamp(), message))

print(repr(messages[0]))
messages = sorted(messages, key=lambda foo: foo[0])
for i in range(len(messages) - 10, len(messages)):
  print("From: " + messages[i][1].get("From"))
  if messages[i][1].__contains__("To"):
    print("To: " + messages[i][1].get("To"))
  else:
    print("To: <not specified>")
  print("Subject: " + messages[i][1].get("Subject"))
  print("Date: " + email.utils.formatdate(timeval = messages[i][0]))
  print("")
exit(0)
