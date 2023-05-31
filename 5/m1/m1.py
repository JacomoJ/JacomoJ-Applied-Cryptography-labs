#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from passlib.hash import argon2
import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50501

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")
    
json_send({
    'command': 'password'
})

pw = bytes.fromhex(json_recv()['res'])
guess = argon2.hash(pw)

json_send({
    'command': 'guess',
    'guess': guess
})

print(json_recv())