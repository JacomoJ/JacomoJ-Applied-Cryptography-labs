#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50690

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"

tn1 = telnetlib.Telnet(host, 50690)
tn2 = telnetlib.Telnet(host, 50600)

def readline1():
    return tn1.read_until(b"\n")

def json_recv1():
    line = readline1()
    return json.loads(line.decode())

def readline2():
    return tn2.read_until(b"\n")

def json_recv2():
    line = readline2()
    return json.loads(line.decode())

def json_send1(req):
    request = json.dumps(req).encode()
    tn1.write(request + b"\n")

def json_send2(req):
    request = json.dumps(req).encode()
    tn2.write(request + b"\n")

json_send2({
    'command': 'token'
})

token = json_recv2()['token']
cs = token['command_string']
mac = token['mac']
# {'command_string': '636f6d6d616e643d68656c6c6f266172673d776f726c64', 'mac': 'f2e240e872b7e8816f0083d87394ba188cbe2011b25f8c16458fbf567eef1d1d'}
print(f'token received {token}')

# cs = b"command=hello&arg=world"
cs = bytes.fromhex(cs)
pad_command = b'&command=flag'
new_command = cs + pad_command
print(f'new_command: {new_command}')

json_send1({
    'command': 'hashpump',
    'mac': mac,
    'data': cs.decode(),
    'append': pad_command.decode()
})

# {'new_hash': 'b183b7609f979e00564fe065fd44572b312ae155d13a56b8d6081b322f8c0033', 'new_data': '636f6d6d616e643d68656c6c6f266172673d776f726c648000000000000000000000000000000000000000000000013826636f6d6d616e643d666c6167'}
res = json_recv1()
print(res)

new_hash = res['new_hash']
new_command = res['new_data']

print(f'new data: {bytes.fromhex(new_command)}')

new_token = {
    'command_string': new_command,
    'mac': new_hash
}

json_send2({
    'command': 'token_command',
    'token': new_token
})

print(json_recv2())
