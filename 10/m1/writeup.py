# %% [markdown]
# # Idea
# The idea is to exploit to malleate a ciphertext and the corresponding tag.
# 
# Ctxt: this is easy, we can use the same nonce, which leads to same counters for all encryptions. Moreover, since we are using CTR mode, we can privide a message which consists of 15 octats of zero as ptxt, to obtain ctxt which is the same as the intended counter. Using the latter, we can create any ctxt of our choose. 
# 
# Tag: this is a bit tricky, but we can exploit the fact that the message length and the keys are fixed, so as the mask if we fix our nonce. This means that the only factor that changes is the ciphertext content. By changing it, we can recover KM^2, and thus we can malleate the tag. More precisely, we do as follows:
# 
# 1. Query the encryption oracle twice with different messages to obtain c1, t1, c2, t2
# 2. Compute KM^2 = ((t1 - t2) * (c1 - c2)^-1) mod p = (c1 - c2) * KM^2 * (c1 - c2)^-1 mod p = KM^2
# 3. Compute the distance from an arbitrary tag to the target tag as diff = (target - c1) mod p
# 4. Construct the target tag: t1 + diff * KM^2 mod p
#    

# %%
#!/usr/bin/env python3
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.number import inverse
from Crypto.Util.strxor import strxor
import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 51001

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
nonce = b'\x00' * 8

m1 = b'\x00' * 15 
m2 = b'\x01' * 15
p = 2**127 - 1

json_send({
    'command': 'encrypt',
    'message': m1.decode(),
    'nonce': nonce.hex()
})

res = json_recv()
# counter = c1, comes for free since we provided m1 = 0...0
c1 = res['ciphertext']
c1 = bytes.fromhex(c1)
tag1 = res['tag']
counter = c1

json_send({
    'command': 'encrypt',
    'message': m2.decode(),
    'nonce': nonce.hex()
})
res = json_recv()
c2 = res['ciphertext']
c2 = bytes.fromhex(c2)
tag2 = res['tag']

# compute KM^2
c1_int = bytes_to_long(c1)
c2_int = bytes_to_long(c2)
tag1_int = bytes_to_long(bytes.fromhex(tag1))
tag2_int = bytes_to_long(bytes.fromhex(tag2))
km_sqr = ((tag1_int - tag2_int) * inverse(c1_int - c2_int, p)) % p

# malleate ctxt 
target = b'Give me a flag!'
target_ctxt = strxor(target, counter)
target_ctxt_int = bytes_to_long(target_ctxt)

# malleate tag
diff_c = (target_ctxt_int - c1_int) % p
target_tag_int = (tag1_int + diff_c * km_sqr) % p

json_send({
    'command': 'decrypt',
    'ciphertext': target_ctxt.hex(),
    'tag': long_to_bytes(target_tag_int).hex(),
    'nonce': nonce.hex()
})

print(json_recv())



