# %%
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50401

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
    

# %%
# Idea: we perform a trivial injection attack to get the flag, like SQL injection. 
# This exploits that the server does not check the format of user's input so we can trick the server to think we are admin.

username = 'jacomo&role=admin'
favorite_coffee = 'espresso'

# Register using injection
json_send({
    'command': 'register',
    'username': username,
    'favourite_coffee': favorite_coffee
})
token = json_recv()['token']

# Login
json_send({
    'command': 'login',
    'token': token
})
res = json_recv()

# change settings
json_send({
    'command': 'change_settings',
    'good_coffee': 'true'
})
res = json_recv()

# get the flag
json_send({
    'command': 'get_coffee'
})

res = json_recv()
print(res)


