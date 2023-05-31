from Crypto.Hash import SHA256
from Crypto.Cipher import AES

iv = bytes.fromhex("e764ea639dc187d058554645ed1714d8")

def generate_aes_key(integer: int, key_length: int):
    seed = integer.to_bytes(2, byteorder='big')
    hash_object = SHA256.new(seed)
    aes_key = hash_object.digest()
    trunc_key = aes_key[:key_length]
    return trunc_key

def decipher(ciphertext, key, iv):
   cipher = AES.new(key, AES.MODE_CBC, iv)
   plaintext = cipher.decrypt(ciphertext)
   return plaintext

f = open('flag.enc', 'r')
ciphertext = f.read()
ciphertext = bytes.fromhex(ciphertext)
f.close()

f = open('plaintextx.data', 'a')
for seed in range(65535):
  key = generate_aes_key(seed, 16)
  plaintext = decipher(ciphertext, key, iv)
  try:
    f.write(plaintext.decode())
    print(ciphertext)
  except:
     pass
  # print(plaintext)

f.close()