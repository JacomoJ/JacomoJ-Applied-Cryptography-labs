# %% [markdown]
# # Idea
# This attack is based on the reuse of K in DSA seen in the lecture.
# 
# First, we note that nonce is generated using the MD5 of the given message, so we can provide two messages that MD5 to the same (k, r).
# 
# By quering the signing oracle with messages m1 and m2, we obtain (r, s1) and (r, s2), which allows us to recover k. 
# 
# Having k, h, r, q, s, with a bit of algebra we can compute the signing key, which allows us to create any signatures. 

# %%
#!/usr/bin/env python3
from Crypto.Util.number import bytes_to_long
from Crypto.Hash import SHA256, MD5, HMAC
from Crypto.Util.number import inverse
import math
from typing import Tuple
import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51000

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

def get_nonce(msg: bytes, sign_key: int, g: int, p: int, q: int) -> Tuple[int, int]:
    # Because we don't trust our server, we will be hedging against randomness failures by derandomising

    h = MD5.new(msg).digest()

    # We begin by deterministically deriving a nonce
    # as specified in https://datatracker.ietf.org/doc/html/rfc6979#section-3.2
    l = 8 * MD5.digest_size
    rlen = math.ceil(q.bit_length() / 8)
    V = bytes([1] * l)
    K = bytes([0] * l)

    K = HMAC.new(K, V + b'\x00' + sign_key.to_bytes(rlen, "big") + h).digest()
    V = HMAC.new(K, V).digest()
    K = HMAC.new(K, V + b'\x01' + sign_key.to_bytes(rlen, "big") + h).digest()
    V = HMAC.new(K, V).digest()

    while True:
        T = b''
        tlen = 0

        while tlen < q.bit_length():
            V = HMAC.new(K, V).digest()
            T += V
            tlen += len(V) * 8

        # Apply bits2int and bring down k to the length of q
        k = int.from_bytes(T, "big")
        k >>= k.bit_length() - q.bit_length()

        r = pow(g, k, p) % q

        if 1 <= k <= q-1 and r != 0:
            break

        K = HMAC.new(K, V + b'\x00').digest()
        V = HMAC.new(K, V).digest()

    return k, r

def DSA_sign(msg: bytes, sign_key: int, g: int, p: int, q: int):
    # Get k and r = (g^k mod p) mod q
    k, r = get_nonce(msg, sign_key, g, p, q)

    # Compute the signature
    h = int.from_bytes(SHA256.new(msg).digest(), "big")
    s = (pow(k, -1, q) * (h + sign_key * r)) % q
    return r, s

# %%
m1 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70'
m2 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70'

target = b'Give me a flag!'

# %%
json_send({
    'command': 'get_params'
})
params = json_recv()
q = params['q']
p = params['p']
g = params['g']

# %%
h1_int = bytes_to_long(SHA256.new(bytes.fromhex(m1)).digest())
h2_int = bytes_to_long(SHA256.new(bytes.fromhex(m2)).digest())

json_send({
    'command': 'sign',
    'message': m1
})
sign1 = json_recv()

json_send({
    'command': 'sign',
    'message': m2
})
sign2 = json_recv()

s1 = sign1['s']
s2 = sign2['s']
r = sign1['r']

k = (inverse(s1 - s2, q) * (h1_int - h2_int)) % q

x = ((s1 * k - h1_int) * inverse(r, q)) % q
r_new, s_new = DSA_sign(target, x, g, p, q)
json_send({
    'command': 'flag',
    'r': r_new,
    's': s_new
})

res = json_recv()

print(res)


