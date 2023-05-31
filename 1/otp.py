plain = "Pay no mind to the distant thunder, Beauty fills his head with wonder, boy"
plain_bytes = bytes(plain, 'utf-8')
key = "bca914890bc40728b3cf7d6b5298292d369745a2592ad06ffac1f03f04b671538fdbcff6bd9fe1f086863851d2a31a69743b0452fd87a993f489f3454bbe1cab4510ccb979013277a7bf"
key_bytes = bytes.fromhex(key)
cipher = b''
for i in range(0, len(plain)):
  cipher += (plain_bytes[i] ^ key_bytes[i]).to_bytes(1, 'little')
print(cipher.hex())