#!/usr/bin/env python3
import spf
import re
import asyncio
import sys

print("Macro Tests:")
tests = open("macro_tests")
state = 0
desc = None
inp = None
comp = None
regexp = None
funcall = None

for line in tests:
    line = line.rstrip()
    if state == 0:
        desc = line
    elif state == 1:
        inp = line
    elif state == 2:
        regexp = None
        comp = line
        if comp == "None":
            comp = None
        elif comp[0] == '"':
            comp = comp[1:-1]
        elif comp[0:2] == 'r"':
            regexp = comp[2:-1]
            comp = None
    elif state == 3:
        funcall = line.split(" ")
        if len(funcall) == 0:
            funcall.append(spf.macro_expand)
        if len(funcall) == 1:  #ipadr
            funcall.append("0.0.0.0")
        if len(funcall) == 2: #domain
            funcall.append("example.com")
        if len(funcall) == 3: # sender
            funcall.append("schmoe@example.com")
        if len(funcall) == 4:
            funcall.append(False)
        if isinstance(funcall[0], str):
            if funcall[0] == "macro_expand":
                funcall[0] = spf.macro_expand
            else:
                print("Invalid test:", repr(funcall))
                break
        if funcall[4] == "False":
            funcall[4] = False
        elif funcall[4] == "True":
            funcall[4] = True
        result = funcall[0](inp, funcall[1], funcall[2], funcall[3], funcall[4])
        status = "FAIL"
        if result == None and comp == None and regexp == None:
            status = "success"
        elif isinstance(result, str) and comp != None and comp == result:
            status = "success"
        elif isinstance(result, str) and regexp != None and re.match(regexp, result):
            status = "success"
        if status != "success":
            print(desc, status, result)
            import pdb
            func = funcall[0]
            funcall[0] = inp
            pdb.runcall(func, *funcall)
        else:
            print(desc, status)
    state = state + 1
    if state > 3:
        state = 0

spftests = [
    ['64.18.0.1', 'google.com', 'ipv4good@google.com', 'pass'],
    ['10.20.30.40', 'google.com', 'ipv4bad@google.com', 'softfail'],
    ['2001:4860:4000::1', 'google.com', 'ipv6good@google.com', 'pass'],
    ['::1', 'google.com', 'ipv6bad@google.com', 'softfail'],
    ['72.14.177.211', 'fugue.com', 'ipv4good@fugue.com', 'pass'],
    ['2600:3c00::f03c:91ff:fedb:80ed', 'fugue.com', 'ipv6good@fugue.com', 'pass'],
    ['72.14.177.201', 'fugue.com', 'ipv4bad@fugue.com', 'fail'],
    ['2600:3c00::f03c:91ff:fedb:80fd', 'fugue.com', 'ipv6bad@fugue.com', 'fail'],
    ['104.129.245.81', 'gmail.com', 'plemon@gmail.com', 'softfail'],
    ['107.190.133.121', 'gmail.com', 'cadwelljack@gmail.com', 'softfail'],
    ['107.190.133.121', 'gmail.com', 'frasergenevieve@gmail.com', 'softfail'],
    ['109.135.17.119', 'gmail.com', 'Yvonne@gmail.com', 'softfail'],
    ['12.130.137.222', 'luv.southwest.com', 'SouthwestAirlines@luv.southwest.com', 'pass'],
    ['133.130.56.192', 'qq.com', '1377540328@qq.com', 'permerror'],
    ['136.147.177.64', 'emails.sierraclub.org', 'reply@emails.sierraclub.org', 'permerror'],
    ['139.78.133.6', 'WARNER.K12.OK.US', 'cjackson@WARNER.K12.OK.US', None],
    ['142.0.81.78', 'burpee.com', 'BurpeeGardens@burpee.com', 'pass'],
    ['142.0.81.79', 'burpee.com', 'BurpeeGardens@burpee.com', 'pass'],
    ['142.54.245.108', 'mail.discovery.com', 'Discovery_Channel@mail.discovery.com', 'pass'],
    ['152.3.189.227', 'frn.com', 'info@frn.com', None],
    ['164.46.224.16', 'gmail.com', 'nalviantonio@gmail.com', 'softfail'],
    ['167.89.18.20', 'standuptoalec.org', 'Info@standuptoalec.org', None],
    ['167.89.23.165', 'movetoamend.org', 'info@movetoamend.org', 'pass'],
    ['167.89.26.124', 'standuptoalec.org', 'Info@standuptoalec.org', None],
    ['167.89.32.32', 'movetoamend.org', 'info@movetoamend.org', 'pass'],
    ['167.89.32.34', 'movetoamend.org', 'info@movetoamend.org', 'pass'],
    ['17.151.1.92', 'insideicloud.icloud.com', 'noreply@insideicloud.icloud.com', 'pass'],
    ['173.203.13.221', 'aclu.org', 'aclu@aclu.org', 'permerror'],
    ['173.203.13.221', 'aclum.org', 'action@aclum.org', 'softfail'],
    ['178.22.147.198', 'Hilton.com', 'CTAC_DT_Hotel@Hilton.com', 'softfail'],
    ['183.79.150.32', 'gmail.com', 'sarahwilliamss890@gmail.com', 'softfail'],
    ['186.85.78.173', 'gmail.com', 'fabianreyesbogota@gmail.com', 'softfail'],
    ['192.64.236.174', 'emails.thenation.com', 'emails@emails.thenation.com', 'pass'],
    ['192.64.236.235', 'grist.org', 'advertising@grist.org', 'permerror'],
    ['192.82.209.247', 'dlcc.org', 'abi.strayer@dlcc.org', 'fail'],
    ['192.82.209.247', 'dlcc.org', 'dave.griggs@dlcc.org', 'fail'],
    ['205.201.135.55', 'mail55.atl51.rsgsv.net', 'BGBulletin=buildinggreen.com@mail55.atl51.rsgsv.net', 'pass'],
    ['205.201.135.55', 'buildinggreen.com', 'BGBulletin@buildinggreen.com', None],
    ['192.82.209.247', 'dlcc.org', 'mark.schauer@dlcc.org', 'fail'],
    ['192.82.209.247', 'dlcc.org', 'michael.sargeant@dlcc.org', 'fail'],
    ['192.82.209.247', 'dlcc.org', 'staff@dlcc.org', 'fail'],
    ['198.2.129.171', 'vpr.net', 'membership@vpr.net', 'pass'],
    ['198.2.129.182', 'gmail.com', 'ryangrim@gmail.com', 'softfail'],
    ['198.2.129.208', 'epi.org', 'newsletter@epi.org', 'permerror'],
    ['198.2.129.66', 'vpr.net', 'membership@vpr.net', 'pass'],
    ['198.2.130.195', 'linktv.org', 'linktvcc@linktv.org', 'permerror'],
    ['198.2.130.44', 'vpr.net', 'membership@vpr.net', 'pass'],
    ['198.2.190.5', 'hillaryclinton.com', 'MassachusettsOrganizing@hillaryclinton.com', 'fail'],
    ['198.202.148.68', 'alternet.org', 'replies@alternet.org', 'pass'],
    ['198.202.148.69', 'demandprogress.org', 'info@demandprogress.org', 'pass'],
    ['199.7.202.38', 'e1.llbean.com', 'llbean@e1.llbean.com', 'pass'],
    ['200.160.158.145', 'sinos.net', 'camthorton@sinos.net', 'pass'],
    ['204.151.185.119', 'live.com', 'allenbrown4u@live.com', 'softfail'],
    ['204.232.230.87', 'care.com', 'careteam@care.com', 'permerror'],
    ['205.201.134.83', 'massdems.org', 'contact@massdems.org', 'neutral'],
    ['207.136.214.66', 'garden.org', 'NGAgardenshop@garden.org', 'permerror'],
    ['208.117.54.141', 'sumofus.org', 'community@sumofus.org', 'pass'],
    ['208.117.54.141', 'sumofus.org', 'us@sumofus.org', 'pass'],
    ['208.117.55.196', 'movetoamend.org', 'info@movetoamend.org', 'pass'],
    ['208.75.123.131', 'fchcc.org', 'jriel@fchcc.org', 'permerror'],
    ['208.75.123.132', 'masscptc.org', 'webmaster@masscptc.org', 'permerror'],
    ['208.75.123.235', 'sover.net', 'msbfc@sover.net', 'softfail'],
    ['208.85.51.243', 'leahyforvermont.com', 'info@leahyforvermont.com', 'pass'],
    ['208.95.134.118', 'hillaryclinton.com', 'info@hillaryclinton.com', 'pass'],
    ['216.27.22.175', 'metopera.org', 'NoReply@metopera.org', 'permerror'],
    ['216.52.210.112', 'stamps.com', 'No-Reply@stamps.com', None],
    ['217.22.160.17', 'me.com', 'hsbcbankontaroi@me.com', 'softfail'],
    ['2607:f8b0:4001:c06::23a', 'googlegroups.com', 'NQpipelineaction@googlegroups.com', 'pass'],
    ['2607:f8b0:4001:c06::23a', 'progress.com', 'moloney@progress.com', 'temperror'],
    ['2607:f8b0:4001:c06::23f', 'googlegroups.com', 'NQpipelineaction@googlegroups.com', 'pass'],
    ['2607:f8b0:4001:c06::240', 'googlegroups.com', 'NQpipelineaction@googlegroups.com', 'pass'],
    ['2607:f8b0:4001:c06::247', 'youtube.com', 'noreply@youtube.com', 'pass'],
    ['2607:f8b0:4002:c07::237', 'googlegroups.com', 'NQpipelineaction@googlegroups.com', 'pass'],
    ['2607:f8b0:4002:c07::247', 'youtube.com', 'noreply@youtube.com', 'pass'],
    ['2607:f8b0:4003:c01::23b', 'mac.com', 'khartlage@mac.com', 'softfail'],
    ['2607:f8b0:400c:c05::23f', 'googlegroups.com', 'NQpipelineaction@googlegroups.com', 'pass'],
    ['2607:f8b0:400d:c04::23c', 'googlegroups.com', 'NQpipelineaction@googlegroups.com', 'pass'],
    ['2607:f8b0:400d:c04::245', 'youtube.com', 'noreply@youtube.com', 'pass'],
    ['2607:f8b0:400d:c09::240', 'juno.com', 'lyoungblood@juno.com', 'neutral'],
    ['2607:f8b0:400e:c03::23d', 'googlegroups.com', 'NQpipelineaction@googlegroups.com', 'pass'],
    ['4.79.195.123', 'wand.org', 'peace@wand.org', 'softfail'],
    ['4.79.195.124', 'caclean.org', 'newsletter@caclean.org', 'temperror'],
    ['50.31.32.206', 'movetoamend.org', 'info@movetoamend.org', 'pass'],
    ['50.31.34.187', 'weareultraviolet.org', 'info@weareultraviolet.org', 'pass'],
    ['50.31.40.102', 'MomsRising.org', 'info@MomsRising.org', 'pass'],
    ['50.31.40.102', 'momsrising.org', 'info@momsrising.org', 'pass'],
    ['50.31.43.174', 'shopmail.pottermore.com', 'no-reply@shopmail.pottermore.com', 'pass'],
    ['50.31.63.95', '350.org', '350@350.org', 'permerror'],
    ['50.56.10.121', 'email.rewards.aarp.org', 'rewardsforgood@email.rewards.aarp.org', 'pass'],
    ['54.240.13.10', 'amazon.com', 'ship-confirm@amazon.com', 'pass'],
    ['54.240.13.13', 'amazon.com', 'order-update@amazon.com', 'pass'],
    ['54.240.13.13', 'amazon.com', 'ship-confirm@amazon.com', 'pass'],
    ['54.240.13.14', 'gc.email.amazon.com', 'gc-orders@gc.email.amazon.com', 'pass'],
    ['54.240.13.16', 'amazon.com', 'customer-reviews-messages@amazon.com', 'pass'],
    ['54.240.13.18', 'amazon.com', 'order-update@amazon.com', 'pass'],
    ['54.240.13.18', 'amazon.com', 'ship-confirm@amazon.com', 'pass'],
    ['54.240.13.20', 'amazon.com', 'cs-reply@amazon.com', 'pass'],
    ['54.240.13.20', 'amazon.com', 'order-update@amazon.com', 'pass'],
    ['54.240.13.22', 'amazon.com', 'delivers@amazon.com', 'pass'],
    ['54.240.13.22', 'amazon.com', 'payments-messages@amazon.com', 'pass'],
    ['54.240.13.24', 'amazon.com', 'ship-confirm@amazon.com', 'pass'],
    ['54.240.13.26', 'amazon.com', 'ship-confirm@amazon.com', 'pass'],
    ['54.240.13.27', 'amazon.com', 'customer-reviews-messages@amazon.com', 'pass'],
    ['54.240.13.31', 'amazon.com', 'cs-reply@amazon.com', 'pass'],
    ['54.240.13.32', 'amazon.com', 'auto-confirm@amazon.com', 'pass'],
    ['54.240.13.36', 'amazon.com', 'auto-confirm@amazon.com', 'pass'],
    ['54.240.13.36', 'amazon.com', 'ship-confirm@amazon.com', 'pass'],
    ['54.240.13.38', 'amazon.com', 'order-update@amazon.com', 'pass'],
    ['54.240.13.40', 'amazon.com', 'order-update@amazon.com', 'pass'],
    ['54.240.13.42', 'amazon.com', 'ship-confirm@amazon.com', 'pass'],
    ['54.240.13.5', 'amazon.com', 'ship-confirm@amazon.com', 'pass'],
    ['54.240.13.6', 'amazon.com', 'auto-confirm@amazon.com', 'pass'],
    ['54.240.13.8', 'amazon.com', 'auto-communication@amazon.com', 'pass'],
    ['54.240.13.9', 'amazon.com', 'customer-reviews-messages@amazon.com', 'pass'],
    ['54.240.15.82', 'amazon.com', 'store_news@amazon.com', 'pass'],
    ['54.64.177.205', 'imf.org', 'noreply@imf.org', 'fail'],
    ['63.146.170.16', 'care2.com', 'actionalerts@care2.com', 'pass'],
    ['63.146.170.191', 'care2team.com', 'petitions@care2team.com', 'pass'],
    ['63.146.170.193', 'care2team.com', 'petitions@care2team.com', 'pass'],
    ['63.146.170.194', 'care2team.com', 'petitions@care2team.com', 'pass'],
    ['63.251.246.24', 'mail.vresp.com', 'Team_Cuomo@mail.vresp.com', 'permerror'],
    ['64.244.120.42', 'npca.org', 'takeaction@npca.org', 'pass'],
    ['64.244.120.47', 'npca.org', 'npca@npca.org', 'pass'],
    ['64.244.120.47', 'popconnect.org', 'president@popconnect.org', 'pass'],
    ['64.244.120.56', 'fwwatch.org', 'act@fwwatch.org', 'permerror'],
    ['64.244.120.60', 'care.org', 'info@care.org', 'pass'],
    ['64.244.120.60', 'lcv.org', 'feedback@lcv.org', 'pass'],
    ['64.244.122.220', 'lcv.org', 'feedback@lcv.org', 'pass'],
    ['64.244.127.141', 'clf.org', 'e-info@clf.org', 'pass'],
    ['64.244.127.144', 'ppfa.org', 'pponline@ppfa.org', 'pass'],
    ['64.244.127.148', 'ppfa.org', 'pponline@ppfa.org', 'pass'],
    ['64.244.127.168', 'ppfa.org', 'actionfund@ppfa.org', 'pass'],
    ['64.244.127.172', 'ppfa.org', 'pponline@ppfa.org', 'pass'],
    ['64.244.127.176', 'ppfa.org', 'pponline@ppfa.org', 'pass'],
    ['64.244.127.182', 'ppfa.org', 'actionfund@ppfa.org', 'pass'],
    ['64.244.127.184', 'ppfa.org', 'actionfund@ppfa.org', 'pass'],
    ['64.94.250.108', 'thehousemajoritypac.com', 'Democrats@thehousemajoritypac.com', None],
    ['64.94.250.8', 'joekennedyforcongress.com', 'campaign@joekennedyforcongress.com', 'pass'],
    ['65.55.116.91', 'msn.com', 'janetconover@msn.com', 'pass'],
    ['66.151.230.135', 'joekennedyforcongress.com', 'campaign@joekennedyforcongress.com', 'pass'],
    ['66.151.230.145', 'naacpms.org', 'info@naacpms.org', 'softfail'],
    ['66.231.87.196', 'email.powells.com', 'newsletter@email.powells.com', 'permerror'],
    ['66.45.103.64', 'ppfa.org', 'actionfund@ppfa.org', 'pass'],
    ['66.45.103.72', 'commoncause.org', 'petitions@commoncause.org', 'pass'],
    ['66.45.103.72', 'ppfa.org', 'pponline@ppfa.org', 'pass'],
    ['67.217.113.11', 'vpr.net', 'jmurphy@vpr.net', 'pass'],
    ['69.174.83.167', 't4america.org', 'info@t4america.org', 'permerror'],
    ['69.174.83.168', 'nirs.org', 'nirsnet@nirs.org', 'permerror'],
    ['69.174.83.170', 'winwithoutwar.org', 'info@winwithoutwar.org', 'permerror'],
    ['69.174.83.182', 'dailykos.com', 'campaigns@dailykos.com', 'temperror'],
    ['69.174.83.184', 'biologicaldiversity.org', 'TheCenter@biologicaldiversity.org', None],
    ['69.174.83.185', 'earthworksaction.org', 'action@earthworksaction.org', 'pass'],
    ['69.174.83.187', 'lwv.org', 'egmacnamara@lwv.org', 'permerror'],
    ['69.174.83.188', 'earthworksaction.org', 'action@earthworksaction.org', 'pass'],
    ['69.174.83.189', 'earthworksaction.org', 'action@earthworksaction.org', 'pass'],
    ['69.174.83.192', 'earthworksaction.org', 'action@earthworksaction.org', 'pass'],
    ['69.174.83.194', 'earthworksaction.org', 'action@earthworksaction.org', 'pass'],
    ['69.174.83.199', 'watchdog.net', 'info@watchdog.net', 'neutral'],
    ['69.41.165.59', 'caclean.org', 'trent.lange@caclean.org', 'pass'],
    ['69.48.252.164', 'endgenocide.org', 'info@endgenocide.org', 'permerror'],
    ['69.48.252.175', 'lcv.org', 'feedback@lcv.org', 'pass'],
    ['69.56.46.240', 'TownHallmail.com', 'THeditor@TownHallmail.com', 'permerror'],
    ['70.42.50.132', 'joekennedyforcongress.com', 'campaign@joekennedyforcongress.com', 'pass'],
    ['74.112.67.134', 'dga.net', 'info@dga.net', 'pass'],
    ['74.121.49.22', 'hillaryclinton.com', 'info@hillaryclinton.com', 'pass'],
    ['8.21.238.144', 'dlcc.org', 'staff@dlcc.org', 'fail'],
    ['8.21.238.150', 'wand.org', 'peace@wand.org', 'softfail'],
    ['8.21.238.152', 'caclean.org', 'newsletter@caclean.org', 'temperror'],
    ['8.21.238.152', 'wand.org', 'peace@wand.org', 'softfail'],
    ['8.21.238.152', 'myngp.com', 'peace@wand.org', 'permerror'],
    ['94.126.144.46', 'presidency.com', 'notice@presidency.com', 'fail']]

loop = asyncio.get_event_loop()

def spf_test_func(test):
    status = yield from spf.check_host(test[0], test[1], test[2])
    if status != test[3]:
        print(repr(test) + ":", status)
        status = yield from spf.check_host(test[0], test[1], test[2], debug=True)
        return False
    return True

tasks = []
for test in spftests:
    tasks.append(asyncio.async(spf_test_func(test)))
co = asyncio.wait(tasks)
loop.run_until_complete(co)
