
#!/usr/bin/env python3
from Crypto.Util.number import long_to_bytes
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256, MD5
from Crypto.Cipher import AES
from passlib.hash import argon2
import telnetlib
import json

target = '9fb7009f8a9b4bc598b4c92c91f43a2c'

with open('./rockyou.txt', 'r', encoding='utf8', errors='ignore') as f:
    while True:
        pw_candidate = f.readline().strip()
        print('\r'+pw_candidate, end='')
        pw_candidate_hash = MD5.new(pw_candidate.encode()).hexdigest()
        if pw_candidate_hash == target:
            print('\n\n'+pw_candidate)
            break
