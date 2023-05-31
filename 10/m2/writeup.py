# %% [markdown]
# # Idea
# The idea is to restrict the intended group of DH key exchange to a small subgroup, which we seen in the lecture.
# This is done by choosing a k such that fixing any generator g in the group and raised it to the k, so the order of h is t, which is small. More precisely, we have the relationship that k = (p-1)/t, that's why the order is t, because the elements repeats every t times. 
# 
# 1. First, we choose a small t and big k, such that k*t has bit length of at least 1024 bits, requested by the server
# 2. Construct the corresponding p that satisfies the relation p = kt + 1, and it's a prime of bit length > 1024 
# 3. Send h and p to the server
# 4. Get back our pk, and guess our sk, which is feasible since we have only t elements in this group
# 5. Send encrypt request, and get back the encrypted flag
# 6. Compute HKDF as same as the server does, which is possible since we have our sk now
# 7. Get the flag

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
PORT = 51002

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
# set params
t = getPrime(8)
k = getRandomInteger(1020)
while True:
    p = k * t + 1
    # print(p.bit_length())
    if isPrime(p) and p.bit_length() > 1024:
        break
    else:
        k = getRandomInteger(1020)
# k = (p-1)//t

g = getRandomInteger(64) % p
h = pow(g, k, p) # h has order t mod n, and t is small
# print('h: ', h)

json_send({
    'command': 'set_params',
    'p': p,
    'g': h
})

res = json_recv()
# print(res)
my_pk = res['bob_pubkey']

# brute force my secret key
my_sk = 0
while True:
    my_sk += 1
    candidate_pk = pow(h, my_sk, p)
    if candidate_pk == my_pk:
        break 

# ask for encryption
json_send({
    'command': 'encrypt'
})

res = json_recv()
# print(res)

other_pk = res['pk']
ciphertext = bytes.fromhex(res['ciphertext'])
tag = bytes.fromhex(res['tag'])
nonce = bytes.fromhex(res['nonce'])

# decrypt
shared = pow(other_pk, my_sk, p)
shared_bytes = shared.to_bytes(512, 'big')
my_pk_bytes = my_pk.to_bytes(512, 'big')
other_pk_bytes = other_pk.to_bytes(512, 'big')

K = HKDF(shared_bytes + other_pk_bytes + my_pk_bytes, 32, salt=b'', num_keys=1, context=b'dhies-enc', hashmod=SHA256)
# print('shared: ', shared_bytes)
# print('bob pk: ', my_pk_bytes)
# print('server pk: ', other_pk_bytes)
# print('K: ', K)
cipher = AES.new(K, AES.MODE_GCM, nonce=nonce)

plaintext = cipher.decrypt_and_verify(ciphertext, tag)

print(plaintext)

# %%



