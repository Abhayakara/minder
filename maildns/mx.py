import dns.resolver
import dns.rdatatype
# This shouldn't be necessary, but for some reason __import__ when
# called from a coroutine, doesn't always work, and I haven't been
# able to figure out why.   Possibly this is a 3.4.0 bug that's fixed
# later, but googling for it hasn't worked.
import dns.rdtypes.ANY.MX
import dns.rdtypes.IN.A
import dns.rdtypes.IN.AAAA
import dns.rdtypes.ANY.SOA
import dns.rdtypes.ANY.NS
import socket
import asyncio

@asyncio.coroutine
def get_exchanger_list(resolver, family=socket.AF_UNSPEC, lim=None, implicit=True):
  resolver = dns.resolver.Resolver()
  resolver.use_edns(0, 0, 1410)
  mxs = {}
  answer = None
  addressable = False
  arecs = None
  a4recs = None

  if family == socket.AF_UNSPEC or family == socket.AF_INET:
    arecs = []
  if family == socket.AF_UNSPEC or family == socket.AF_INET6:
    a4recs = []

  if lim:
    if lim[0] == 0:
      raise TooManyQueries
    else:
      lim[0] = lim[0] - 1
  try:
    answer = yield from resolver.aquery(domain, "MX")

  except dns.resolver.NoAnswer:
    if not implicit:
      return None
    
    # No answer means there's no MX record, so look for an A or
    # AAAA record.
    
    yield from self.fetch_addrs(resolver, domain, arecs, a4recs, lim)
    if ((arecs and len(arecs) > 0) or
        a4recs and len(a4recs) > 0):
      mxs = { 0: [ { "exchange" : domain,
                     "a": arecs, "aaaa": a4recs } ] }
      addressable = True

  except (NXDOMAIN, TooManyQueries):
    raise
  
  except:
    return None

  else:
    for mx in answer:
      if mx.rdtype == dns.rdatatype.MX:
        # If exchange addresses were included in the additional
        # section, use those.
        # XXX for SPF, relying on the additional section may be a mistake:
        # what if it includes some, but not all, relevant data?
        for rrset in answer.response.additional:
          if rrset.name == mx.exchange:
            if rrset.rdtype == dns.rdatatype.A and arecs != None:
              for rdata in rrset:
                arecs.append(rdata.address)
                addressable = True
            elif rrset.rdtype == dns.rdatatype.AAAA and a4recs != None:
              for rdata in rrset:
                a4recs.append(rdata.address)
                addressable = True
        # Otherwise, fetch A and/or AAAA records for exchange
        if not addressable:
          yield from self.fetch_addrs(resolver, mx.exchange, arecs, a4recs, lim)
        if ((arecs and len(arecs) > 0) or
            a4recs and len(a4recs) > 0):
          entry = { "exchange": mx.exchange,
                    "a": arecs, "aaaa": a4recs}
          if mx.preference in mxs:
            mxs[mx.preference].append(entry)
          else:
            mxs[mx.preference] = [entry]
          addressable = True

  # If we didn't get a single server IP address either out of the
  # MX query chain or the A/AAAA query on the name if there was no
  # MX, then we can't deliver to this address.
  if not addressable:
    return None

  return mxs

  # Make a list of all the addresses to try, in order of preference.
  # We prefer IPv6 for the first attempt, but interleave IPv6 and
  # IPv4 addresses in case one transport is working and the other
  # is not.   The interleaving is per-exchange, so we always try
  # exchanges in order of preference and, among exchanges with the
  # same preference, one exchange at a time.
def compute_address_list(self, mxs, family, limit):
  abp = []
  preferences = list(mxs.keys())
  preferences.sort()
  # Iterate across preference levels
  for pref in preferences:
    addrs = []
    abp.append(addrs)
    exchanges = mxs[pref]
    # Iterate across exchanges at a given preference level
    for exchange in exchanges:
      arecs = exchange['a']
      qrecs = exchange['aaaa']
      name = exchange['exchange']
      # Interleave the IPv6 and IPv4 addresses for this exchange.
      lim = max(len(arecs), len(qrecs))
      for i in range(0, lim):
        if i < len(qrecs):
          addrs.append((qrecs[i], socket.AF_INET6, name))
        if i < len(arecs):
          addrs.append((arecs[i], socket.AF_INET, name))
  return abp

  # Do the A and AAAA queries in parallel.
  @asyncio.coroutine
  def fetch_addrs(self, resolver, name, arecs, a4recs, lim):
    if lim and lim[0] == 0:
      raise TooManyQueries
    lim[0] = lim[0] - 1
    aco = resolver.aquery(name, "A", raise_on_no_answer=False)
    a4co = resolver.aquery(name, "AAAA", raise_on_no_answer=False)
    co = asyncio.gather(aco, a4co)
    (aans, a4ans) = yield from co
    if aans.rrset != None:
      for rdata in aans:
        arecs.append(rdata.address)
    if a4ans.rrset != None:
      for rdata in a4ans:
        a4recs.append(rdata.address)
    
