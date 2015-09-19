import dns.resolver
import dns.rdtypes.ANY.MX
import dns.rdtypes.ANY.TXT
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.name
import asyncio
import mx
import struct
import socket
import time
import urllib.parse
import sys

# Given an input string, iterate across the input string looking for spf macros,
# and expanding each one.   On success, return the string with the macros expanded;
# on failure, return None.
def macro_expand(input, ipaddr, domain, sender, exp, debug=False):
  hunks = input.split('%')
  quoted = True # first hunk is never a macro.
  escaped = False
  output = ""
  for hunk in hunks:
    if quoted:
      if escaped:
        output = output + '%' + hunk
      else:
        output = output + hunk
      escaped = False
      quoted = False
    elif len(hunk) == 0:
      escaped = True
      quoted  = True
    elif hunk[0] == '_':
      output = output + " " + hunk[1:]
    elif hunk[0] == '-':
      output = output + "%20" + hunk[1:]
    elif hunk[0] != '{':
      if debug:
        print("Macro expansion failed: invalid macro characer", hunk[0])
      return None
    else:
      endbrace = hunk.find("}")
      # There _must_ be an end brace before the next %, or it's a syntax error.
      if endbrace == -1:
        if debug:
          print("Macro expansion failed: no end brace")
        return None
      macro = hunk[1:endbrace]
      hunk = hunk[endbrace + 1:]
      if len(macro) < 1:
        if debug:
          print("Macro expansion failed: nothing in macro")
        return None
      # Okay, we have an actual macro; for clarity, the work of expanding it
      # has been extracted into its own function.
      expansion = macro_expand_worker(macro, ipaddr, domain, sender, exp, debug)
      if expansion == None:
        return None
      output = output + expansion + hunk
  # If escaped is True here, it means that a % character appeared by itself in the
  # source text, which is invalid.
  if escaped:
    if debug:
      print("Macro expansion failed: singular escape")
    return None
  return output

# Once a macro has been located in the string, this function is called to expand it.
def macro_expand_worker(macro, ipaddr, domain, sender, exp, debug=False):
  letter = macro[0]
  digits = ""
  reverse = False
  delimiters = None
  macro = macro[1:]
  if len(macro) > 0:
    digits = ""
    while len(macro) > 0 and macro[0] in "0123456789":
      digits = digits + macro[0]
      macro = macro[1:]
    if len(macro) > 0 and macro[0] == 'r':
      reverse = True
      macro = macro[1:]
    if len(macro) > 0:
      delimiters = macro
      for char in delimiters:
        # Make sure all the delimiters are valid.
        if char not in ".-+,/_=":
          if debug:
            print("Invalid delimiter:", char)
          return None
  # Uppercase has special meaning...
  urlencode = False
  if letter.isupper():
    urlencode = True
    letter = letter.lower()
  if letter not in "slodipvhcrt":
    if debug:
      print("Invalid macro letter:", letter)
    return None
  # We don't currently support exp, but we still have to syntax check it
  if letter in "crt" and not exp:
    if debug:
      print("Macro letter invalid in non-explanation context:", letter)
    return None
  if letter == "s":
    expansion = sender
  elif letter == "l":
    # Sender has already been syntax-checked
    parts = sender.split("@")
    expansion = parts[0]
  elif letter == "o":
    parts = sender.split("@")
    expansion = parts[1]
  elif letter == "d":
    expansion = domain
  elif letter == "i":
    expansion = ipaddr
  elif letter == "p":
    # XXX this is not recommended by the spec, and is arguably a terrible
    # idea, hence not recommended.   I'm reluctant to implement it, but should
    # check to see if mail is being scored down because of it.
    return None
  elif letter == "v":
    if addr_family(ipaddr) == socket.AF_INET6:
      expansion = "ip6"
    else:
      expansion = "in-addr"
  elif letter == "h":
    # I haven't implemented helo_domain because I think it's a bad idea:
    # too many things are valid here, so syntax checking it is problematic.
    # Should gather stats on whether this is ever used.   Seems like a very
    # chancy thing to use.   I guess if you were clever with TTLs you could
    # use it as a nonce, but to what end?
    expansion = "unknown"
  elif letter == "c":
    expansion = ipaddr
  elif letter == "r":
    expansion = "unknown"
  elif letter == "t":
    expansion = str(time.time())
  else:
    if debug:
      print("Logic error:", letter)
    # logic error
    return None
  # Now process transformers/delimiters
  if digits != "" or reverse or delimiters != None:
    expansion = macro_transform(expansion, digits, reverse, delimiters)
    if expansion == None:
      return None
  if urlencode:
    expansion = urllib.parse.quote(expansion)
  return expansion

# This function does any transformation or reversal that's called for, including
# handling delimiters.
def macro_transform(expansion, digits, reverse, delimiters):
  if delimiters == None:
    parts = expansion.split(".")
  else:
    if len(delimiters) == 1:
      parts = expansion.split(delimiters)
    else:
      # I think it's cleaner to do this iteratively rather than with
      # regexps.
      parts = []
      found = True
      while found:
        found = False
        offset = len(expansion)
        for delim in delimiters:
          off = expansion.find(delim)
          if off != -1 and off < offset:
            offset = off
            found = True
        parts.append(expansion[:offset])
        if offset < len(expansion):
          expansion = expansion[offset+1:]
  # The RFC doesn't say so explicitly, but the examples indicate that
  # we reverse the parts _before_ chopping off the lhs.
  if reverse:
    parts.reverse()
  if digits != "":
    chop = int(digits) # already syntax checked above.
    if chop < len(parts):
      parts = parts[-chop:]
  expansion = ".".join(parts)
  return expansion
  
def addr_family(addr):
  # We do not syntax-check the address here.   It's not possible for an IPv6 address
  # to not contain a colon, nor for an IPv4 address to contain one, so that's enough
  # to differentiate.
  if ':' in addr:
    return socket.AF_INET6
  return socket.AF_INET

# if all the bits in map1 and map2 that are covered by the specified prefix
# length match, return True else return False.  Assumes withs are the same.
def bitmatch(map1, map2, width, debug=False):
  bytes = int(width / 8)
  residual = width - bytes * 8
  for i in range(0, bytes):
    if map1[i] != map2[i]:
      return False
  if residual == 0:
    return True
  part1 = map1[bytes]
  part2 = map2[bytes]
  mask = (256 - (256 >> residual))
  if (part1 & mask) == (part2 & mask):
    return True
  return False
    
def cidr_match(cidr, bitmap, addr, family, debug=False):
  if isinstance(bitmap, str):
    # By the time we get here, bitmap should either be a pile of bits or a valid
    # text representation of an IP address, so although we catch the exception here
    # it really shouldn't be possible, so we treat it as a mismatch rather than a
    # faiure.
    try:
      bitmap = socket.inet_pton(family, bitmap)
    except:
      return False
  if isinstance(addr, str):
    try:
      addr = socket.inet_pton(family, addr)
    except:
      return False
  status = bitmatch(bitmap, addr, cidr, debug)
  return status


class Directive:
  def __init__(self, worker, resolver, debug=False):
    self.matched = False
    self.resolver = resolver
    self.worker = worker
    self.debug = debug

  def validate(self, term, ipaddr, domain, sender):
    if term[0] in "+-?~":
      # If there is an explicit qualifier, chop it off.
      qualifier = term[0]
      term = term[1:]
    else:
      qualifier = "+"
    off = term.find(":")
    if off != -1:
      self.parameter = macro_expand(term[off + 1:],
                                    ipaddr, domain, sender, False, self.debug)
      if self.parameter == None:
        return "permerror"
      name = term[:off]
    elif "/" in term:
      slashoff = term.find("/")
      self.parameter = term[slashoff:]
      name = term[0:slashoff]
    else:
      self.parameter = None
      name = term

    method = getattr(self, "process_" + name, None)
    if method == None:
      if self.debug:
        print("Invalid directive:", name)
      return "permerror"
    self.process_func = method
    method = getattr(self, 'validate_' + name, None)
    if method == None:
      return "permerror" # should never happen!
    if method() == "permerror":
      return "permerror"
    if qualifier == "+":
      self.status = "pass"
    elif qualifier == '-':
      self.status = "fail"
    elif qualifier == "~":
      self.status = "softfail"
    elif qualifier == "?":
      self.status = "neutral"
    self.name = name
    return None
  
  @asyncio.coroutine
  def process(self, ipaddr, domain, sender):
    status = yield from self.process_func(ipaddr, domain, sender)
    return status
  
  # Never valid
  def validate_unknown(self):
    return "permerror"

  # domain-spec
  def validate_domain(self):
    if self.parameter != None:
      try:
        self.domain_name = dns.name.from_text(self.parameter)
      except:
        if self.debug:
          print("Invalid delimiter:", char)
        return "permerror"
    else:
      self.domain_name = None
    return None

  # [ ":" domain-spec ] [ "/" ipv4-cidr [ "/" ipv6-cidr ]
  def validate_domain_cidr(self):
    if self.parameter != None and '/' in self.parameter:
      parts = self.parameter.split('/')
      if len(parts) > 3:
        if self.debug:
          print("too many parts in cidr:", repr(parts))
        return "permerror"
      try:
        self.ipv4_cidr = int(parts[1])
      except:
        if self.debug:
          print("not an integer:", parts[1])
        return "permerror"
      if self.ipv4_cidr < 0 or self.ipv4_cidr > 32:
        if self.debug:
          print("invalid ipv4 prefix length:", self.ipv4_cidr)
        return "permerror"
      if len(parts) > 2:
        try:
          self.ipv6_cidr = int(parts[2])
        except:
          if self.debug:
            print("not an integer:", parts[2])
          return "permerror"
        if self.ipv6_cidr < 0 or self.ipv6_cidr > 128:
          if self.debug:
            print("invalid ipv6 prefix length:", self.ipv4_cidr)
          return "permerror"
      else:
        self.ipv6_cidr = 128
        self.parameter = parts[0]
    else:
      self.ipv4_cidr = 32
      self.ipv6_cidr = 128
    return self.validate_domain()

  # "all"    
  def validate_all(self):
    if self.parameter != None:
      if self.debug:
        print("all takes no parameter:", self.parameter)
      return "permerror"
  @asyncio.coroutine
  def process_all(self, ipaddr, domain, sender):
    self.matched = True
    return self.status

  # "include" ":" domain-spec
  def validate_include(self):
    if self.parameter == None:
      if self.debug:
        print("include requires parameter")
      return "permerror"
    return self.validate_domain()
  @asyncio.coroutine
  def process_include(self, ipaddr, domain, sender):
    if self.parameter == None:
      self.parameter = domain
    status = yield from self.worker(ipaddr, self.parameter, sender, self.debug)
    if status == "pass":
      self.matched = True
      return self.status
    elif status == "fail":
      self.matched = False
      return None
    elif status == "softfail":
      self.matched = False
      return None
    elif status == "neutral":
      self.matched = False
      return None
    elif status == "temperror":
      self.matched = True
      return "temperror"
    elif status == "permerror":
      self.matched = True
      return "permerror"
    elif status == None:
      self.matched = True
      return "permerror"
    return None
    
  def validate_a(self):
    return self.validate_domain_cidr()
  @asyncio.coroutine
  def process_a(self, ipaddr, domain, sender):
    if self.domain_name == None:
      self.domain_name = domain
    try:
      if addr_family(ipaddr) == socket.AF_INET:
        cidr = self.ipv4_cidr
        family = socket.AF_INET
        response = yield from self.resolver.aquery(self.domain_name, "a",
                                                   raise_on_no_answer=True)
      else:
        cidr = self.ipv6_cidr
        family = socket.AF_INET6
        response = yield from self.resolver.aquery(self.domain_name, "aaaa",
                                                   raise_on_no_answer=True)
    except dns.resolver.NoAnswer:
      if self.debug:
        print(self.domain_name + ": No Answer")
      return None
    except Exception as x:
      if self.debug:
        print(self.domain_name + ":", str(x))
      return "temperror"
    for rrd in response:
      if cidr_match(cidr, rrd.address, ipaddr, family, self.debug):
        self.match = True
        return self.status
    return None
      
  def validate_mx(self):
    return self.validate_domain_cidr()
  @asyncio.coroutine
  def process_mx(self, ipaddr, domain, sender):
    if self.parameter == None:
      self.parameter = domain
    try:
      mxs = yield from mx.get_exchanger_list(self.parameter,
                                             self.resolver, addr_family(ipaddr), [10], False)
      # If this domain has no MX record, it can't match.
      if mxs == None:
        return None
    except Exception as x:
      # The exception would be too many queries, which indicates an attack,
      # hence a permanent error.
      if self.debug:
        print(self.parameter + ":", str(x))
      return "permerror"
    for pref in mxs:
      for exchange in mxs[pref]:
        if addr_family(ipaddr) == socket.AF_INET:
          for addr in exchange["a"]:
            if cidr_match(self.ipv4_cidr, addr, ipaddr, socket.AF_INET, self.debug):
              self.matched = True
              return self.status
        else:
          for addr in exchange["aaaa"]:
            if cidr_match(self.ipv6_cidr, addr, ipaddr, socket.AF_INET6, self.debug):
              self.matched = True
              return self.status
    return None

  # This mechanism is recommended against.  If a site is using it, it is a spam site
  # or a DDoS site or else run by someone who can benefit from a bit of negative feedback
  # so that they get around to fixing their configuration.
  def validate_ptr(self):
    if self.debug:
      print("ptr directive not supported")
    return "permerror"
  @asyncio.coroutine
  def process_ptr(self, ipaddr, domain, sender):
    pass

  def validate_ipaddr(self, family):
    if family == socket.AF_INET:
      width = 32
    else:
      width = 128
    if '/' in self.parameter:
      chunks = self.parameter.split("/")
      if len(chunks) != 2:
        if self.debug:
          print("too many prefix lengths", self.parameter)
        return "permerror"
      try:
        self.cidr = int(chunks[1])
        if self.cidr < 0 or self.cidr > width:
          if self.debug:
            print("invalid cidr width:", self.cidr, ">", width)
          return "permerror"
      except:
        if self.debug:
          print("Not an integer:", chunks[1])
        return "permerror"
      self.parameter = chunks[0]
    else:
      self.cidr = width
    try:
      self.cidr_bitmap = socket.inet_pton(family, self.parameter)
    except Exception as e:
      if self.debug:
        print("Not a valid IP address:", self.parameter)
      return "permerror"
    return None

  def validate_ip4(self):
    return self.validate_ipaddr(socket.AF_INET)

  @asyncio.coroutine
  def process_ip4(self, ipaddr, domain, sender):
    if cidr_match(self.cidr, self.cidr_bitmap, ipaddr, socket.AF_INET, self.debug):
      self.matched = True
      return self.status
    return None
  
  def validate_ip6(self):
    return self.validate_ipaddr(socket.AF_INET6)
  @asyncio.coroutine
  def process_ip6(self, ipaddr, domain, sender):
    if cidr_match(self.cidr, self.cidr_bitmap, ipaddr, socket.AF_INET6, self.debug):
      self.matched = True
      return self.status
    return None
    
  def validate_exists(self):
    return self.validate_domain(self)
  @asyncio.coroutine
  def process_exists(self, ipaddr, domain, sender):
    if self.domain_name == None:
      self.domain_name = domain
    try:
      response = yield from self.resolver.aquery(self.domain_name, "a",
                                                 raise_on_no_answer=True)
    except dns.resolver.NoAnswer:
      return None
    except dns.resolver.NXDOMAIN:
      return None
    except Exception as x:
      if self.debug:
        print("exists(" + str(self.domain_name) + "):", str(x))
      return "temperror"

@asyncio.coroutine
def check_host(ipaddr, domain, sender, debug=False):
  limiter = [0]
  resolver = dns.resolver.Resolver()
  resolver.use_edns(0, 0, 1410)
  resolver.nameservers = ["127.0.0.1"]

  @asyncio.coroutine
  def check_host_worker(ipaddr, domain, sender, debug=False):
    limiter[0] = limiter[0] + 1
    if limiter[0] > 10:
      if debug:
        print("DNS query limiter stopped search.")
      return "permerror"

    # RFC 7208 section 4.3: check for invalid domain name
    try:
      name = dns.name.from_text(domain)
    except:
      if debug:
        print("failure:", domain, " is not a valid domain name")
      return "permerror"
    # RFC 7208 section 4.3: check for existence of local-part
    # We are assuming that the caller has produced some
    # vaguely valid sender, either from the MAIL FROM:
    # or HELO/EHLO.   For validating From: headers,
    # combining the source IP address and sender isn't
    # sufficient to say that the use isn't permitted, but
    # it is sufficient to say that the use _is_ permitted.
    if '@' not in sender:
      try:
        sdo = dns.name.from_text(sender)
      except:
        if debug:
          print("failure:", sender, " is not a valid domain name")
        return "permerror"
      sender = "postmaster@" + sender
    else:
      parts = sender.split("@")
      if len(parts) != 2:
        return "permerror"
      if parts[0] == '':
        sender = "postmaster@" + parts[1]
      try:
        sdo = dns.name.from_text(parts[1])
      except:
        if debug:
          print("failure:", parts[1], " is not a valid domain name")
        return "permerror"
      
    spfs = []
    try:
      spfRecord = yield from resolver.aquery(domain, "TXT", raise_on_no_answer=True)
    except dns.resolver.NoAnswer:
      if debug:
        print(domain, "IN TXT: No Answer")
      return None
    except Exception as x:
      if debug:
        print(domain, "IN TXT:", str(x))
      return "temperror"
    else:
      for rr in spfRecord:
        text = "".join(rr.strings)
        if text.startswith("v=spf1 "):
          spfs.append(text[7:])
    if len(spfs) == 0:
      if debug:
        print(domain, "IN TXT: No valid SPF record")
      return None
    if len(spfs) > 1:
      if debug:
        print("More than one SPF record found.")
      return "permerror"

    # Terms are separated by exactly one space.
    # terms = *( 1*SP ( directive / modifier ) )
    if debug:
      print(spfs[0])
    terms = spfs[0].split(" ")
    redirect = None
    modifiers = {}
    directives = []
    for term in terms:
      if len(term) == 0:
        if debug:
          print("syntax error: zero-length term")
        return "permerror"
      # Eliminate the possibility that this is a modifier first,
      # because they are easy to detect.
      elif "=" in term:
        sides = term.split("=")
        if len(sides) != 2:
          if debug:
            print("bogus modifier")
          return "permerror"
        # modifiers can only appear once.
        if sides[0] in modifiers:
          if debug:
            print("Duplicate modifier:", sides[0])
          return "permerror"
        exp = False
        if sides[0] == "exp":
          exp = True
        expansion = macro_expand(sides[1], ipaddr, domain, sender, exp)
        if expansion == None:
          return "permerror"
        modifiers[sides[0]] = sides[1]
      else:
        # By default, then, this is a directive.
        directive = Directive(check_host_worker, resolver, debug)
        if directive.validate(term, ipaddr, domain, sender) == "permerror":
          return "permerror"
        directives.append(directive)
    for directive in directives:
      status = yield from directive.process(ipaddr, domain, sender)
      # If this directive matched, don't process any later directives.
      if directive.matched:
        if debug:
          print("Matched:", directive.name)
        return status
      # If this directive returned a definite answer, return that answer
      # (e.g., tempfail, etc.)
      if status != None and status != "neutral":
        if debug:
          print("Status:", status)
        return status
    # Since we survived the directives, try the modifiers.
    for modifier in modifiers:
      if modifier == "exp":
        # We could really care less.
        pass
      elif modifier == "redirect":
        if debug:
          print("Redirect:", modifiers[modifier])
        status = yield from check_host_worker(ipaddr, modifiers[modifier], sender, debug)
        if debug:
          print("Status:", status)
        return status
    return "neutral"

  status = yield from check_host_worker(ipaddr, domain, sender, debug)
  if ipaddr == "54.204.34.3":
    print("status:", status)
    
  # If the SPF record is broken, or there is no SPF record, then allow
  # the A record for the domain, if any.
  if status == "permerror" or status == None:
    print("re-checking", ipaddr, "at", domain)
    directive = Directive(None, resolver, debug)
    if directive.validate("+a", ipaddr, domain, sender) == "permerror":
      return "permerror"
    status = yield from directive.process(ipaddr, domain, sender)
    print("status:", repr(status))
  return status
