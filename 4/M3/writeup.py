# %%
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import telnetlib
import json

BLOCK_SIZE = 16

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50403

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

# %% [markdown]
# # Idea
# The idea is similar to the task we did in lab2, the difference now is that we have to xor with the plaintext block before our target.
# 
# We first make a request, where we use the **prepand_pad** to pad the plaintext such that the secret byte appears in the last block as its first byte, following by the pad bytes '\x0f', here is the block representation of our plaintext to the server: 
# 
# ptxt_blocks = | block_1 | block_2 | block_3 | block_target
# 
# Then we save the last ciphertext block as our **target**, and we bruteforce it by trying all possible bytes. 
# 
# In order to do so, we try to guess by inserting new blocks in the middle of the original plaintext and make requests until we obtained a block_guess which is equal to our target, here is the block representation of our subsequent plaintext:
# 
# ptxt_blocks = | block_1 | block_2 | block_3 | block_guess | block_3 | block_target
# 
# After 10 tries, we request the flag. 

# %%
for i in range(10):
    # by setting filename and data like this, the secret byte will be the first byte in the last block
    filename = 'f.txt'
    prepend_pad = b'aaaaaaaaaaaa'
    postpend_pad = b'aaa'
    data = prepend_pad + postpend_pad
    dummy_secret_byte = b'\x00' # not relevant, just for testing 
    ptxt = (
        b"filename="
        + filename.encode()
        + b"&data="
        + data
        + b"&secret_byte="
        + dummy_secret_byte
    )

    # not relevant, ptxt contains the last block which only has our dummy secret byte
    ptxt_blocks = blockify(ptxt)

    # this is the block that we need to use to xor our guessing block
    exploit_block = ptxt_blocks[-2]

    # send the first request by pushing the secret byte to the end
    json_send({
        'command': 'encrypt',
        'file_name': filename,
        'data': data.hex()
    })

    res = json_recv()
    iv = res['iv']
    ctxt = res['ctxt']
    ctxt_blocks = blockify(bytes.fromhex(ctxt))
    # this block containes the secret byte and the padding b'0x0f' x 15
    target_block = ctxt_blocks[-1]

    # bruteforce the secret byte
    for secret_byte in range(256):
        secret_byte = bytes([secret_byte])
        # padding is needed to create a new block
        secret_byte_pad = pad(secret_byte, BLOCK_SIZE)
        
        # this contains two blocks, the first one is the same as the block used to xor the real secret byte
        # the second one is the our guess secret byte
        guess = exploit_block + secret_byte_pad

        # this is needed to push to have exact blocks, such that the last blocks are the same as the last two blocks we obtained one the first request
        data = prepend_pad + guess + postpend_pad 

        # not relevant, just for testing
        ptxt = (
                b"filename="
                + filename.encode()
                + b"&data="
                + data
                + b"&secret_byte="
                + secret_byte
        )
        ptxt_pad = pad(ptxt, BLOCK_SIZE)
        ptxt_blocks = blockify(ptxt_pad)
        # print('ptxt blockified: ', ptxt_blocks)

        json_send({
            'command': 'encrypt',
            'file_name': filename,
            'data': data.hex()
        })
        ctxt_guess = json_recv()['ctxt']
        ctxt_guess_blocks = blockify(bytes.fromhex(ctxt_guess))

        # in our case the guessed block should be the -3th block
        target_candidate = ctxt_guess_blocks[-3]
        if target_candidate == target_block:
            json_send({
                'command': 'solve',
                'solve': secret_byte.hex()
            })
            print(json_recv())

json_send({
    'command': 'flag'
})
print(json_recv())


