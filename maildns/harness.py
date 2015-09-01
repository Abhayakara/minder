#!/usr/bin/env python3
import spf
import re

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
    ["64.18.0.1", "google.com", "ipv4good@google.com", "pass"],
    ["10.20.30.40", "google.com", "ipv4bad@google.com", "softfail"],
    ["2001:4860:4000::1", "google.com", "ipv6good@google.com", "pass"],
    ["::1", "google.com", "ipv6bad@google.com", "softfail"],
    ["72.14.177.211", "fugue.com", "ipv4good@fugue.com", "pass"],
    ["2600:3c00::f03c:91ff:fedb:80ed", "fugue.com", "ipv6good@fugue.com", "pass"],
    ["72.14.177.201", "fugue.com", "ipv4bad@fugue.com", "fail"],
    ["2600:3c00::f03c:91ff:fedb:80fd", "fugue.com", "ipv6bad@fugue.com", "fail"]]
for i in range(0, len(spftests)):
    test = spftests[i]
    status = spf.check_host(test[0], test[1], test[2])
    print(test[2] + ":", status, test[3])
