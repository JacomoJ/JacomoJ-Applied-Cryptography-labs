# %% [markdown]
# # Idea
# The idea is to use the multiplicative homomorphism of RSA under the same encryption key. 
# 
# Given c = m^e mod N, if we multiply it with 2^e mod N, this is equivalent to (2 * m)^e mod N, in other words, we shift the bits to the left by one position, then send this new ciphertext c' to the server. One of the three events would happen:
# - Decryption success, succeded by chance
# - "Eror", which means that we are shifting the bits in the padding of the ptxt
# - "Error", we stop here since it means that we successfully moved the first bit of M (as defined in the handout) in the most significant byte of m, that allows us to compute the length. 

# %%
#!/usr/bin/env python3
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Hash import SHA256, MD5, HMAC
from Crypto.Util.number import getRandomInteger, getPrime, isPrime
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import HKDF
from typing import Tuple
import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51003

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
def get_challenge():
    json_send({
        'command': 'get_challenge'
    })
    res = json_recv()
    # print(res)
    challenge = res['challenge']
    challenge = bytes.fromhex(challenge)
    challenge = int.from_bytes(challenge, 'big')
    
    return challenge

# %%
def solve_challenge(N, e, challenge):
    shift: int = pow(2, e, N)
    ctxt = (shift * challenge) % N
    for counter in range(0, 1024):
        json_send({
            'command': 'decrypt',
            'ctxt': ctxt.to_bytes(1024 // 8, 'big').hex()
        })
        res = json_recv()
        print(res)
        # print('counter: ', counter)
        if 'error' in res and 'Eror' not in res['error']:
            break
        else:
            ctxt = (shift * ctxt) % N

    i = 1024 - 8 - counter 

    # print('m_big_length: ', 1024 - 8 - counter + 1)
    json_send({
        'command': 'solve',
        'i': i
    })

    res = json_recv()

    # print(res)
    

# %%
json_send({
    'command': 'get_params'
})
res = json_recv()
N = res['N']
e = res['e']

for i in range(256):
    challenge = get_challenge()
    solve_challenge(N, e, challenge)

json_send({
    'command': 'flag'
})

print(json_recv())

# %%



