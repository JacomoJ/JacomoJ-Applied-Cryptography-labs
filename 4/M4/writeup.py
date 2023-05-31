# %% [markdown]
# # Idea
# The idea is different from M3 because I need to know the content of the block before the byte that I need to guess, which is not possible since the bytes before the last byte is part of the flag.
# 
# Instead, I guess from the first byte of the flag onward. To do so, I need to know exact size of the flag so I can determine how much to prepad such that the byte that I need to guess appears as the last byte of the "guess_block" that is a block with everything that we know except for the last byte. Then, I create 256 blocks that is equal to the guess_block execpt for the last byte and send them to the server so I can perform comparison to find the right byte.

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
PORT = 50404

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


# %%
# we first determine the exact length of the flag, this servers as stopping criteria when we found the flag
exploit_length = len(b"filename=" + b"&data=" + b"&flag=")
json_send({
    'command': 'encrypt',
    'file_name': '',
    'data': ''
})
response = json_recv()
ctxt = bytes.fromhex(response['ctxt'])

# prev_len contains exploit_length + len(flag) + data_pad, 
# prev_len - exploit_length is the upper bound for the length of the flag
prev_len = len(ctxt)
data_pad = b''
# keep incrementing data_pad until the length of ctxt changes
# this means that the plaintext fit exactly into the blocks
# thus len(data_pad) indicates the len of the padding that was added initially 
while prev_len == len(ctxt):
    data_pad += b'0'
    json_send({
        'command': 'encrypt',
        'file_name': '',
        'data': data_pad.hex()
    })
    response = json_recv()
    ctxt = bytes.fromhex(response['ctxt'])
len_flag = prev_len - (len(data_pad) + exploit_length)

# now we find the number of prepend padding to push the first letter of the flag
# to the last letter of the an arbitrary block, where everything before it is known
initial_pad_length = 0
curr_index = 1
while initial_pad_length < len_flag:
    initial_pad_length += 16
    curr_index += 1
# +9 because we can make the first letter of the flag at the end of the block
initial_pad_length += 9 

filename = 'f'
prepend_pad = b'0' * initial_pad_length
m0 = b'filename=f&data='
exploit_block = b'0000000000000000'
# guess_block containes the last byte as the byte that we have to guess
guess_block = b'000000000&flag='
flag = b'' 
flag_found = False

while len_flag > 0:
    # first encrypt to get the correct ciphertext 
    json_send({
        'command': 'encrypt',
        'file_name': filename,
        'data': prepend_pad.hex()
    })
    response = json_recv()
    ctxt = bytes.fromhex(response['ctxt'])
    ctxt_blocks = blockify(ctxt)

    # block that has the last byte that we have to guess
    target = xor(ctxt_blocks[curr_index], exploit_block)

    guesses = []
    # we generate all possible guesses for the last byte and create a block for each
    # this is because we simply consider this CBC mode as ECB but xored with the previous
    # plaintext block, we can revert the xor later
    for byte_guess in range(256):
        byte_guess = bytes([byte_guess])
        guesses.append(guess_block + byte_guess)

    guesses_bytes = b''.join(guesses)
    json_send({
        'command': 'encrypt',
        'file_name': filename,
        'data': guesses_bytes.hex()
    })
    response = json_recv()
    c_prev = bytes.fromhex(response['iv'])
    ctxt = bytes.fromhex(response['ctxt'])
    ctxt_blocks = blockify(ctxt)

    # this is needed so we can xor the ciphertext blocks back and to the comparisons
    guesses.insert(0, m0)

    # start guessing
    for i in range(256):
        # print('guess: ', ctxt_blocks[i])
        our_guess = xor(ctxt_blocks[i], c_prev)
        if our_guess == target:
            # i - 1 because ctxt has a block of iv at the beginning, so there is no direct correspondence of byte-index
            secret_byte = bytes([i - 1])
            flag += secret_byte
            
            # we need to shift everything to the left by one byte
            # so the new flag byte that we have to guess appears at the end of the guess_block
            exploit_block = exploit_block[1:] + bytes([guess_block[0]])

            # same for our guess_block
            guess_block = guess_block[1:] + secret_byte 
            # print('new guess block: ', guess_block)

            # same for out prepend_pad
            prepend_pad = prepend_pad[1:]
            len_flag -= 1
        # to xor back
        c_prev = guesses[i]
print(flag)



# %%



