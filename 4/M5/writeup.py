# %%
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from datetime import datetime, timezone
import re
import telnetlib
import json

BLOCK_SIZE = 16

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50405

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

def blockify(a):
    return [a[i : i + BLOCK_SIZE] for i in range(0, len(a), BLOCK_SIZE)]

@staticmethod
def parse_repr(metadata):
    """Parses a string representation of a Message, returning the metadata fields"""

    majv, minv, src, rcv, ts = re.match(
        r"Montone Protocol \(v(\d+)\.(\d+)\) message from (\d+) to (\d+), sent on (.+)\.",
        metadata,
    ).groups()

    majv = int(majv).to_bytes(2, "little")
    minv = int(minv).to_bytes(1, "little")
    src = int(src).to_bytes(4, "little")
    rcv = int(rcv).to_bytes(4, "little")
    ts = int(datetime.fromisoformat(ts).timestamp()).to_bytes(4, "little")
    return src + rcv + ts + majv + minv

# %% [markdown]
# # Idea
# The idea is to exploit the fact that the server leaks the second ciphertext block c2, which it assumes to be the metadata. We can move the secret block as the second block to make the server leak that with a little of computation, more precisely at the beginning we have:
# 
# c1 = Enc(m1 xor c0) xor m0
# 
# c2 = Enc(m2 xor c1) xor m1
# 
# c3 = Enc(m3 xor c2) xor m2
# 
# m1 = Dec(m0 xor c1) xor c0
# 
# m2 = Dec(m1 xor c2) xor c1
# 
# m3 = Dec(m2 xor c3) xor c2
# 
# and by moving the secret block we need to satisfy the following:
# 
# c0' = c0
# 
# c1' = c2
# 
# c2' = c3 xor m2 xor m1
# 
# m0' = c1 xor c2 xor m0
# 
# m1' = m1
# 
# m2' = Dec(m1' xor c2') xor c1' = Dec(m1 xor c3 xor m2 xor m1) xor c2 = Dec(c3 xor m2) xor c2 = m3
# 
# Then we simply send c0' || c1' || c2' || ... to get m2' which has the first 15 bytes as m3. But note that the server does not leak the last byte of the second block, and in order to find it in a reasonable amount of attempts, we use binary search. 

# %%
json_send({
    'command': 'init'
})
res = json_recv()
m0 = bytes.fromhex(res['m0'])
c0 = bytes.fromhex(res['c0'])
ctxt = bytes.fromhex(res['ctxt'])
ctxt_blocks = blockify(ctxt)

# make the first metadata leak to get the real metadata
json_send({
    'command': 'metadata_leak',
    'm0': m0.hex(),
    'c0': c0.hex(),
    'ctxt': ctxt.hex()
})
metadata = json_recv()['metadata']

# the real metadata
m2 = parse_repr(metadata) + b'\x02' 

c1 = ctxt_blocks[0]
c2 = ctxt_blocks[1]
c3 = ctxt_blocks[2]
# play the trick
m0_new = xor(m0, xor(c1, c2))
m1 = b'MONTONE-PROTOCOL'
c0_new = c0
c1_new = c2
c2_new = xor(c3, xor(m1, m2))

# generate a block of 16 bytes at random, used pad the ciphertext
pad_block = get_random_bytes(BLOCK_SIZE)

# binary search to find the last byte of the secret
min_pad_blocks = 0
max_pad_blocks = 255
flag = b''
while min_pad_blocks < max_pad_blocks:
    mid = (min_pad_blocks + max_pad_blocks) // 2
    ctxt_new = [c1_new, c2_new] + [pad_block] * mid
    ctxt_new = b''.join(ctxt_new)

    json_send({
        'command': 'metadata_leak',
        'm0': m0_new.hex(),
        'c0': c0_new.hex(),
        'ctxt': ctxt_new.hex()
    })
    res = json_recv()

    if 'error' in res:
        min_pad_blocks = mid + 1
    else:
        max_pad_blocks = mid

mid = (min_pad_blocks + max_pad_blocks) // 2
ctxt_new = [c1_new, c2_new] + [pad_block] * mid
ctxt_new = b''.join(ctxt_new)

# the server will leak the secret, except the last byte
json_send({
        'command': 'metadata_leak',
        'm0': m0_new.hex(),
        'c0': c0_new.hex(),
        'ctxt': ctxt_new.hex()
})
metadata = json_recv()['metadata']

secret_byte = max_pad_blocks
flag = parse_repr(metadata) + bytes([secret_byte])
json_send({
    'command': 'flag',
    'solve': flag.decode()
})
print(json_recv())



