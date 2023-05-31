#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes

"""
This is a simple client implementation based on telnetlib that can help you connect to the remote server.

Taken from https://cryptohack.org/challenges/introduction/
"""

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = False

# Remember to change the port if you are re-using this client for other challenges
PORT = 50221

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


def get_len():

    pre_block_cnt = -1

    for i in range(16):

        request = {
            "command": 'encrypt',
            "prepend_pad": ('a'*i).encode().hex()
            # "command": "solve",
            # "ciphertext": "ff7837b501ffd7f49d895d83dad0344f"   #  "token": "534554454320415354524f4e4f4d59"
        }
        json_send(request)

        response = json_recv()

        print(response, len(response['res']), i)

        if (len(response['res']) / 32 == pre_block_cnt + 1):
            print(f"padding len {i}")
            return i

        pre_block_cnt = len(response['res']) / 32



for i in range(5):

    padding_len = get_len()

    if padding_len == None:
        padding_len = 0

    # brute force the last byte
    # the last block is 'p' + '\x0f'* 0xf

    request = {
        "command": 'encrypt',
        "prepend_pad": ('a'*(padding_len+1)).encode().hex()
        # "command": "solve",
        # "ciphertext": "ff7837b501ffd7f49d895d83dad0344f"   #  "token": "534554454320415354524f4e4f4d59"
    }
    json_send(request)

    target = json_recv()['res'][-32:]
    print(target)

    for i in range(256):
        request = {
            "command": 'encrypt',
            "prepend_pad": (long_to_bytes(i) + b'\x0f'*0xf).hex()
            # "command": "solve",
            # "ciphertext": "ff7837b501ffd7f49d895d83dad0344f"   #  "token": "534554454320415354524f4e4f4d59"
        }
        json_send(request)

        res = json_recv()['res'][:32]

        # print(res)
        if res == target:
            print(f"yes, {long_to_bytes(i).decode()}")

            request = {
                "command": "solve",
                "solve": long_to_bytes(i).decode()
                # "prepend_pad": ('a'*(padding_len+1)).encode().hex()
                
                # "ciphertext": "ff7837b501ffd7f49d895d83dad0344f"   #  "token": "534554454320415354524f4e4f4d59"
            }
            json_send(request)

            recv = json_recv()
            print(recv)

            break

flag = json_recv()
print(flag)