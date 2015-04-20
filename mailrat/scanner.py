#!/usr/bin/env python3

import mailbox
import email
import email.parser
import email.utils
import operator
import re

ksantiRL = re.compile(r"from toccata.fugue.com.*by.*ksanti", flags = re.DOTALL + re.MULTILINE)
toccataRL1 = re.compile(r"\s*by.*toccata.fugue.com", flags = re.DOTALL)
toccataRL2 = re.compile(r".*; (.*)$", flags = re.DOTALL)

class headerMessageFactory(mailbox.MaildirMessage):
  def __init__(self, file):
    parser = email.parser.BytesParser()
    message = parser.parse(file, headersonly=True)
    return super().__init__(message)

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
