#! /usr/bin/python3.4

# Overview:
#
# This file implements the minimal SMTP protocol as defined in RFC 5321.
# The 
#
# Based on python smtpd module written by:
#
# Author: Barry Warsaw <barry@python.org>
# 
#
# TODO:
#
# - support mailbox delivery
# - alias files
# - Handle more ESMTP extensions
# - handle error codes from the backend smtpd

import sys
import os
import errno
import getopt
import time
import socket
import asyncio
import collections
import ssl
import base64
from warnings import warn
from email._header_value_parser import get_addr_spec, get_angle_addr

__all__ = ["SMTPServer"]

program = sys.argv[0]
__version__ = 'Python SMTP protocol server version 0.1';


class Devnull:
    def write(self, msg): pass
    def flush(self): pass


NEWLINE = '\n'
EMPTYSTRING = ''
COMMASPACE = ', '
DATA_SIZE_DEFAULT = 33554432


class SMTPServer(asyncio.Protocol):
    COMMAND = 0
    DATA = 1
    AUTH_PLAIN = 2
    debugstream = Devnull()
    authenticated = False

    def __init__(self):
        self.data_size_limit = DATA_SIZE_DEFAULT
        self.received_lines = []
        self.smtp_state = self.COMMAND
        self.seen_greeting = ''
        self.mailfrom = None
        self.rcpttos = []
        self.received_data = ''
        self.num_bytes = 0
        self.extended_smtp = False
        self.line_oriented = True
        self.received_string = ""
        self.strict_newline = False

    def connection_made(self, transport):
        self.transport = transport
        try:
            self.peer = transport.get_extra_info("peername")
        except OSError as err:
            # a race condition  may occur if the other end is closing
            # before we can get the peername
            self.close()
            if err.args[0] != errno.ENOTCONN:
                raise
            return
        print('Peer:', repr(self.peer), file=self.debugstream)
        self.push('220 greetings.')

    # Overrides base class for convenience
    def push(self, msg):
        print("Resp: ", str(msg), file=self.debugstream)
        self.transport.write(bytes(msg + '\r\n', 'ascii'))

    # Implementation of base class abstract method
    # We do line separation here.   Anything higher level
    # than a line is handled by the process_line method
    def data_received(self, data):
        if self.line_oriented:
            try:
                dstr = str(data, encoding="ascii", errors="strict")
            except:
                self.push("500 non-ASCII character sequence encountered.")
                self.transport.close()
                return
            self.received_string = self.received_string + dstr
            self.num_bytes = self.num_bytes + len(dstr)

            # Extract any lines.   SMTP is a lockstep protocol, so
            # if the other end is for real, there should only be one,
            # but we do not detect or exclude exuberant senders.
            # If the received data doesn't end in a newline, this
            # loop exits when the last full line has been processed,
            # and we anticipate that the partial line will be
            # completed in a subsequent call.
            while self.num_bytes > 0:
                nlp = self.received_string.find("\n")
                crp = self.received_string.find("\r")

                # No line terminator reached yet.
                if nlp == -1 and crp == -1:
                    # SMTP only allows 1000 bytes per line.
                    if self.num_bytes > 1000:
                      self.push("500 too many bytes in a single line.")
                      self.close()
                    return
                elif crp == -1 or crp > nlp:
                    self.push("500 bare newline (ASCII 10) encountered.")
                    self.transport.close()
                    return
                elif nlp == -1 or nlp != crp + 1:
                    self.push("500 bare CR (ASCII 13) encountered.")
                    self.transport.close()
                    return

                # extract the line, excluding the newline
                line = self.received_string[:crp]

                # retain the rest of the input data.
                self.received_string = self.received_string[nlp+1:]
                self.num_bytes = len(self.received_string)

                self.process_line(line)
        else:
            self.push("451 Internal error.")
            
    # Implementation of base class abstract method
    def process_line(self, line):
        print('Data:', repr(line), file=self.debugstream)
        if self.smtp_state == self.COMMAND:
            if not line:
                self.push('500 Error: bad syntax')
                return
            method = None
            i = line.find(' ')
            if i < 0:
                command = line.upper()
                arg = None
            else:
                command = line[:i].upper()
                arg = line[i+1:].strip()
            method = getattr(self, 'smtp_' + command, None)
            if not method:
                self.push('500 Error: command "%s" not recognized' % command)
                return
            method(arg)
            return
        elif self.smtp_state == AUTH_PLAIN:
            auth_plain(line)
            return
        else:
            if self.smtp_state != self.DATA:
                self.push('451 Internal confusion')
                self.num_data_bytes = 0
                self.received_lines = []
                return
            if self.data_size_limit and self.num_data_bytes > self.data_size_limit:
                self.push('552 Error: Too much mail data')
                self.num_data_bytes = 0
                self.received_lines = []
                return

            # Append this to the accumulated message; de-transparency-ize
            # lines with leading dots (RFC 5321 section 4.5.2), and if we
            # get a dot by itself, that's the end of the data.
            if line == ".":
              self.process_data()
              return

            if len(line) > 1 and line[0] == ".":
              line = line[1:]

            self.num_data_bytes = self.num_data_bytes + len(line)
            self.received_lines.append(line)

    def process_data(self):
        self.received_data = NEWLINE.join(self.received_lines)
        status = self.process_message(self.peer,
                                      self.mailfrom,
                                      self.rcpttos,
                                      self.received_data)
        self.rcpttos = []
        self.mailfrom = None
        self.smtp_state = self.COMMAND
        self.num_data_bytes = 0
        self.received_lines = []
        if not status:
            self.push('250 OK')
        else:
            self.push(status)

    # This should be overridden by the subclass.
    def process_message(self, peer, mailfrom, rcpttos, message):
      return "451 not implemented."

    # SMTP and ESMTP commands
    def smtp_HELO(self, arg):
        if not arg:
            self.push('501 Syntax: HELO hostname')
            return
        if self.seen_greeting:
            self.push('503 Duplicate HELO/EHLO')
        else:
            self.seen_greeting = arg
            self.extended_smtp = False
            self.push('250 And a hearty HELO to you too!')

    def smtp_EHLO(self, arg):
        if not arg:
            self.push('501 Syntax: EHLO hostname')
            return
        if self.seen_greeting:
            self.push('503 Duplicate HELO/EHLO')
        else:
            self.seen_greeting = arg
            self.extended_smtp = True
            if self.data_size_limit:
                self.push('250-SIZE %s' % self.data_size_limit)
            # If we don't have SSL, advertise anonymous as the only valid
            # authentication mechanism, in hopes that if there is a client
            # out there dumb enough to send PLAIN over an unencrypted link,
            # this will confuse it.
            if self.transport.get_extra_info("cipher") == None:
                self.push('250-AUTH ANONYMOUS')
            else:
                self.push('250-AUTH PLAIN')
            self.push('250 HELP')

    def smtp_NOOP(self, arg):
        if arg:
            self.push('501 Syntax: NOOP')
        else:
            self.push('250 OK')

    def smtp_QUIT(self, arg):
        # args is ignored
        self.push('221 Bye')
        self.transport.close()

    def _strip_command_keyword(self, keyword, arg):
        keylen = len(keyword)
        if arg[:keylen].upper() == keyword:
            return arg[keylen:].strip()
        return ''

    def _getaddr(self, arg):
        if not arg:
            return '', ''
        if arg.lstrip().startswith('<'):
            address, rest = get_angle_addr(arg)
        else:
            address, rest = get_addr_spec(arg)
        if not address:
            return address, rest
        return address.addr_spec, rest

    def _getparams(self, params):
        # Return any parameters that appear to be syntactically valid according
        # to RFC 1869, ignore all others.  (Postel rule: accept what we can.)
        params = [param.split('=', 1) for param in params.split()
                                      if '=' in param]
        return {k: v for k, v in params if k.isalnum()}

    def smtp_HELP(self, arg):
        if arg:
            extended = ' [SP <mail parameters]'
            lc_arg = arg.upper()
            if lc_arg == 'EHLO':
                self.push('250 Syntax: EHLO hostname')
            elif lc_arg == 'HELO':
                self.push('250 Syntax: HELO hostname')
            elif lc_arg == 'MAIL':
                msg = '250 Syntax: MAIL FROM: <address>'
                if self.extended_smtp:
                    msg += extended
                self.push(msg)
            elif lc_arg == 'RCPT':
                msg = '250 Syntax: RCPT TO: <address>'
                if self.extended_smtp:
                    msg += extended
                self.push(msg)
            elif lc_arg == 'DATA':
                self.push('250 Syntax: DATA')
            elif lc_arg == 'RSET':
                self.push('250 Syntax: RSET')
            elif lc_arg == 'NOOP':
                self.push('250 Syntax: NOOP')
            elif lc_arg == 'QUIT':
                self.push('250 Syntax: QUIT')
            elif lc_arg == 'VRFY':
                self.push('250 Syntax: VRFY <address>')
            else:
                self.push('501 Supported commands: EHLO HELO MAIL RCPT '
                          'DATA RSET NOOP QUIT VRFY')
        else:
            self.push('250 Supported commands: EHLO HELO MAIL RCPT DATA '
                      'RSET NOOP QUIT VRFY')

    def smtp_VRFY(self, arg):
        if arg:
            address, params = self._getaddr(arg)
            if address:
                self.push('252 Cannot VRFY user, but will accept message '
                          'and attempt delivery')
            else:
                self.push('502 Could not VRFY %s' % arg)
        else:
            self.push('501 Syntax: VRFY <address>')

    def smtp_MAIL(self, arg):
        if not self.seen_greeting:
            self.push('503 Error: send HELO first');
            return
        print('===> MAIL', arg, file=self.debugstream)
        syntaxerr = '501 Syntax: MAIL FROM: <address>'
        if self.extended_smtp:
            syntaxerr += ' [SP <mail-parameters>]'
        if arg is None:
            self.push(syntaxerr)
            return
        arg = self._strip_command_keyword('FROM:', arg)
        address, params = self._getaddr(arg)
        if not address:
            self.push(syntaxerr)
            return
        if not self.extended_smtp and params:
            self.push(syntaxerr)
            return
        if not address:
            self.push(syntaxerr)
            return
        if self.mailfrom:
            self.push('503 Error: nested MAIL command')
            return
        params = self._getparams(params.upper())
        if params is None:
            self.push(syntaxerr)
            return
        size = params.pop('SIZE', None)
        if size:
            if not size.isdigit():
                self.push(syntaxerr)
                return
            elif self.data_size_limit and int(size) > self.data_size_limit:
                self.push('552 Error: message size exceeds fixed maximum message size')
                return
        if len(params.keys()) > 0:
            self.push('555 MAIL FROM parameters not recognized or not implemented')
            return
        self.mailfrom = address
        print('sender:', self.mailfrom, file=self.debugstream)
        self.push('250 OK')

    def smtp_RCPT(self, arg):
        if not self.seen_greeting:
            self.push('503 Error: send HELO first');
            return
        print('===> RCPT', arg, file=self.debugstream)
        if not self.mailfrom:
            self.push('503 Error: need MAIL command')
            return
        syntaxerr = '501 Syntax: RCPT TO: <address>'
        if self.extended_smtp:
            syntaxerr += ' [SP <mail-parameters>]'
        if arg is None:
            self.push(syntaxerr)
            return
        arg = self._strip_command_keyword('TO:', arg)
        address, params = self._getaddr(arg)
        if not address:
            self.push(syntaxerr)
            return
        if params:
            if self.extended_smtp:
                params = self._getparams(params.upper())
                if params is None:
                    self.push(syntaxerr)
                    return
            else:
                self.push(syntaxerr)
                return
        if not address:
            self.push(syntaxerr)
            return
        if params and len(params.keys()) > 0:
            self.push('555 RCPT TO parameters not recognized or not implemented')
            return
        if not address:
            self.push('501 Syntax: RCPT TO: <address>')
            return
        # XXX caller is responsible for sending error response if validation fails.
        if not self.validate_rcptto(address):
          return
        self.rcpttos.append(address)
        print('recips:', self.rcpttos, file=self.debugstream)
        self.push('250 OK')

    def validate_rcptto(self, address):
      return True

    def smtp_RSET(self, arg):
        if arg:
            self.push('501 Syntax: RSET')
            return
        # Resets the sender, recipients, and data, but not the greeting
        self.mailfrom = None
        self.rcpttos = []
        self.received_data = ''
        self.smtp_state = self.COMMAND
        self.push('250 OK')

    def smtp_DATA(self, arg):
        if not self.seen_greeting:
            self.push('503 Error: send HELO first');
            return
        if not self.rcpttos:
            self.push('503 Error: need RCPT command')
            return
        if arg:
            self.push('501 Syntax: DATA')
            return
        self.smtp_state = self.DATA
        self.num_data_bytes = 0
        self.received_lines = []
        self.push('354 End data with <CR><LF>.<CR><LF>')

    # Commands that have not been implemented
    def smtp_EXPN(self, arg):
        self.push('502 EXPN not implemented')

    def smtp_AUTH(self, arg):
        if self.mailfrom != None or self.rcpttos or self.num_bytes > 0:
            self.push("503 not permitted during transaction.")
        if self.authenticated:
            self.push("503 already authenticated.")
            return
        
        fields = arg.split(" ")
        if arg == "" or len(fields) > 2:
            self.push("500 Syntax: AUTH METHOD[ <initial response>]")

        if fields[0] == "PLAIN":
            if self.transport.get_extra_info("cipher") == None:
                self.push("538-Your mail program just revealed your password.")
                self.push("538-Please switch to a mail program made by")
                self.push("538 someone competent.")
                syslog(syslog.LOG_ERROR,
                       "PLAIN authentication method used without TLS.");
                return
            if len(fields) == 1:
                self.push("334 ");
                self.state = self.AUTH_PLAIN
                return
            self.auth_plain(fields[1])
            return
        self.push("504 %s auth mechanism was not advertised." % fields[0])

    def auth_plain(self, b64):
        self.smtp_state = self.COMMAND
        if b64 == "*":
            self.push("501 authentication rejected.")
            return
        try:
            data = base64.standard_b64decode(b64)
        except:
            self.push("501 invalid base64 response.")
            return

        username = None
        password = None
        try:
            (username, password) = data.split(b"\x00")
        except Exception as e:
            self.push("501 invalid authentication data: %s" % str(e))
            print("data: ", data)
            return

        if self.authenticate(username, password):
            self.authenticated = True
            self.authenticated_user = username
            self.push("235 Authenticated.")
        else:
            self.push("535 Invalid credentials.")
    
