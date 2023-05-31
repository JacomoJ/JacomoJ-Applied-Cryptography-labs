#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1, HMAC
from Crypto.Cipher import AES
from passlib.hash import argon2
import telnetlib
import json
import hmac
import itertools

SALT = 'b49d3002f2a089b371c3'
HASH = 'd262db83f67a37ff672cf5e1d0dfabc696e805bc'

salt_bytes = bytes.fromhex(SALT)
hash_bytes = bytes.fromhex(HASH)

a_z = range(97, 123)

pw_candidate = b''
for combination in itertools.product(a_z, repeat=6):
    pw_candidate = bytes(combination)
    h = hmac.new(pw_candidate, salt_bytes, 'sha1')
    if h.digest() == hash_bytes:
        print(pw_candidate)