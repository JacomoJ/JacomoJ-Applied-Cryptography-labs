# %%
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
PORT = 50402

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

# %%
json_send({
    'command': 'flag'
})
res = json_recv()

m0 = bytes.fromhex(res['m0'])
c0 = bytes.fromhex(res['c0'])
ctxt = bytes.fromhex(res['ctxt'])
ctxt_blocks = [ctxt[i : i + BLOCK_SIZE] for i in range (0, len(ctxt), BLOCK_SIZE)]

c_prev = c0
m_prev = m0
ptxt = []
ptxt_block_correct = b''
c0_pad = b''
for curr_cblock in ctxt_blocks:
    for i in range(BLOCK_SIZE):
        # try all possible bytes
        for byte_exploit in range(256):
            byte_exploit = bytes([byte_exploit])
            same_c0 = c_prev[ : (BLOCK_SIZE - i) - 1]
            c0_exploit = same_c0 + byte_exploit + c0_pad
            json_send({
                'command': 'decrypt',
                'm0': m_prev.hex(),
                'c0': c0_exploit.hex(),
                'ctxt': curr_cblock.hex()
            })
            res = json_recv()
            if 'error' not in res:
                prepend_zeros = b'\x00' * ((BLOCK_SIZE - i) - 1)
                ptxt_block_exploit = pad(prepend_zeros, BLOCK_SIZE)
                correct_byte = xor(ptxt_block_exploit, xor(c0_exploit, c_prev))[-(i + 1)] 
                ptxt_block_correct = bytes([correct_byte]) + ptxt_block_correct

                tmp_ptxt_block = prepend_zeros + ptxt_block_correct

                # correct padding with less one prepend zero
                ptxt_block_exploit = pad(prepend_zeros[:-1], BLOCK_SIZE)
                c0_pad = xor(ptxt_block_exploit, xor(c_prev, tmp_ptxt_block))[-(i + 1):] 
                break
                # c0_pad = bytes([c0_pad])
    print(ptxt_block_correct)
    ptxt.append(ptxt_block_correct)
    m_prev = ptxt_block_correct
    c_prev = curr_cblock
    ptxt_block_correct = b''
print(b''.join(ptxt))


