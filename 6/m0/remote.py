# Jiajun Jiang
# Legi: 19-980-812

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
PORT = 50600

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

def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))   

BLOCK_SIZE = 16

json_send({
    'command': 'token'
})

token = json_recv()['token']
cs = token['command_string']
cs = bytes.fromhex(cs)
mac = token['mac']
print(token)
json_send({
    'command': 'token_command',
    'token': token
})

print(json_recv())

pad_command = b'&command=flag'
new_command = b'command=hello&arg=world' + pad_command
print('new command', new_command)
new_hash = 'b183b7609f979e00564fe065fd44572b312ae155d13a56b8d6081b322f8c0033'

new_token = {
    'command_string': new_command.hex(),
    'mac': new_hash
}
new_token = {
    'command_string': '636f6d6d616e643d68656c6c6f266172673d776f726c648000000000000000000000000000000000000000000000013826636f6d6d616e643d666c6167',
    'mac': new_hash
}

json_send({
    'command': 'token_command',
    'token': new_token
})

print(json_recv())

