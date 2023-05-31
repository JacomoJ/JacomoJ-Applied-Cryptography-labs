#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50690)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

json_send({
    "command": "hashpump",
    "mac": "f2e240e872b7e8816f0083d87394ba188cbe2011b25f8c16458fbf567eef1d1d",
    "data": "command=hello&arg=world",
    "append": "&command=flag",
})

print(json_recv())
