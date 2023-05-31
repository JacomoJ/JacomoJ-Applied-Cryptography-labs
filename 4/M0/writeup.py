# %%
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = False

# Remember to change the port if you are re-using this client for other challenges
PORT = 50400

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
    

# %% [markdown]
# # Idea
# We will perform the "Meet-in-the-middle" attack, i.e., exploit the fact that $E_{k_1}(p) = D_{k_2}(c_2) = c_1$.

# %%
# Generate all possible combination of 2 bytes key and SHA256 to create an AES instance for each of them
ciphers = set()
for i in range(256):
    for j in range(256):
        key = SHA256.new(bytes([i, j])).digest()
        ciphers.add(AES.new(key, AES.MODE_ECB))

# %%
# Send the random plaintext, get the ciphertext and store them into a set
plaintext = get_random_bytes(16)
ctxt_dict = set()
# Compute the encryption with all keys
for cipher in ciphers:
  ctxt_dict.add(cipher.encrypt(plaintext))

for i in range(64):
  print('attemp: ', i+1)
  guess_bit = 1
  json_send({
    "command": "query",
    "m": plaintext.hex()
  })
  ctxt_hex = json_recv()["res"]
  ctxt = bytes.fromhex(ctxt_hex)

  # Bruteforce D_k2(ctxt2) 
  for cipher in ciphers:
    ctxt_guess = cipher.decrypt(ctxt)
    # If we can decrypt, then we are in the AES world
    if ctxt_guess in ctxt_dict:
      guess_bit = 0
      break
  # if we cannot decrypt, then PRP world
  json_send({
  "command": "guess",
  "b": guess_bit
  })
  mess = json_recv()['res']
  print(mess)

json_send({
    "command": "flag"
})
flag = json_recv()["flag"]
print(flag)


