# %% [markdown]
# # Idea
# We still plays the trick in M5, but in this case we have to generelize the computation. 
# 
# More precisely, for each round r, given the original ctxt blocks:
# 
# c0_r = ctxt[0]
# 
# c1_r = ctxt[r + 1]
# 
# c2_r = c[round + 2] xor m[round + 1] xor m1
# 
# m0' = m0 xor c1 xor c[round + 1]
# 
# m1' = m1
# 
# and we want m2' = m[round + 2].

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
PORT = 50406

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

# %%
# request the original ctxt first, parse the data
json_send({
    'command': 'flag'
})
res = json_recv()

m0 = bytes.fromhex(res['m0'])
c0 = bytes.fromhex(res['c0'])
ctxt = bytes.fromhex(res['ctxt'])
ctxt_blocks = blockify(ctxt)
len_ctxt = len(ctxt_blocks)

# make the first metadata leak to get the real metadata
json_send({
    'command': 'metadata_leak',
    'm0': m0.hex(),
    'c0': c0.hex(),
    'ctxt': ctxt.hex()
})
metadata = json_recv()['metadata']

secret_byte = b'\x03' # this is fixed

# the real metadata
m1 = b'MONTONE-PROTOCOL'
m2 = parse_repr(metadata) + secret_byte
c1 = ctxt_blocks[0] # fixed
curr_index = 1 
flag = b''

while curr_index < len_ctxt - 1:
    # print('curr_index: ', curr_index)
    ci = ctxt_blocks[curr_index]
    cip1 = ctxt_blocks[curr_index + 1]

    # play the trick
    m0_new = xor(m0, xor(c1, ci))
    c0_new = c0
    c1_new = ci
    c2_new = xor(cip1, xor(m1, m2))

    # generate a block of 16 bytes at random, used to pad the ciphertext
    pad_block = get_random_bytes(BLOCK_SIZE)

    # binary search to find the last byte of the secret
    min_pad_blocks = 0
    max_pad_blocks = 255
    curr_flag_block = b''
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

    secret_byte = bytes([mid])

    # m2 is always the correct block leaked by the server
    m2 = parse_repr(metadata) + secret_byte
    flag += m2
    curr_index += 1

print(flag)


# %%
'''
msg_blocks:  [b'MONTONE-PROTOCOL', b'9\x05\x00\x00\xc1\x06\x00\x00\xcf\x80\x1dd\x01\x00\x00\x03', b'message_type=fla', b'g&lab=4&graded=T', b'rue\r\r\r\r\r\r\r\r\r\r\r\r\r', b'Thank you for us', b'ing Montone mess', b'aging services. ', b'Here is a flag t', b'hat you will not', b' be able to obta', b'in: flag{longer_', b'test_flag}\x06\x06\x06\x06\x06\x06']
'''


