from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1
from Crypto.Util.Padding import pad, unpad

class StrangeCBC():
    def __init__(self, key: bytes, iv: bytes = None, block_length: int = 16):
        """Initialize the CBC cipher.
        """

        if iv is None:
            iv = bytes.fromhex('89c0d7fef96a38b051cb7ef8203dee1f')
        self.iv = iv
        self.key = key
        self.block_length = block_length
        self.cipher = AES.new(self.key, AES.MODE_ECB)

    def xor(self, X, Y):
        return bytes(x ^ y for (x, y) in zip(X, Y))

    def encrypt(self, plaintext: bytes):
        """Encrypt the input plaintext using AES-128 in strange-CBC mode:

        C_i = E_k(P_i xor C_(i-1) xor 1336)
        C_0 = IV

        Uses IV and key set from the constructor.

        Args:
            plaintext (bytes): input plaintext.

        Returns:
            bytes: ciphertext, starting from block 1 (do not include the IV)
        """
        print('input plaintext: ', plaintext)
        plaintext = pad(plaintext, self.block_length)
        print('padded plaintext: ', plaintext)
        ptxt_vec = [plaintext[i:i+self.block_length] for i in range(0, len(plaintext), self.block_length)]
        
        curr_c = self.iv
        ciphertext = b''
        block_1336 = (1336).to_bytes(16, 'big')
        for ptxt_block in ptxt_vec:
            c_block = self.xor(curr_c, self.xor(block_1336, ptxt_block))
            ciphertext += self.cipher.encrypt(c_block)
            curr_c = c_block
        print('output ciphertext: ', ciphertext)
        return ciphertext

    def decrypt(self, ciphertext: bytes):
        """Decrypt the input ciphertext using AES-128 in strange-CBC mode.

        Uses IV and key set from the constructor.

        Args:
            ciphertext (bytes): input ciphertext.

        Returns:
            bytes: plaintext.
        """
        print('input ciphertext: ', ciphertext)
        ctxt_vec = [ciphertext[i : i + self.block_length] for i in range(0, len(ciphertext), self.block_length)]
        plaintext = b''
        block_1336 = (1336).to_bytes(16, 'big')
        curr_c = self.iv

        for ctxt_block in ctxt_vec:
            decrypted_c = self.cipher.decrypt(ctxt_block)
            plaintext += self.xor(decrypted_c, self.xor(curr_c, block_1336))
            curr_c = ctxt_block
        print('len padded plaintext: ', len(plaintext))
        print('padded plaintext: ', plaintext)
        plaintext = unpad(plaintext, self.block_length)
        print('output plaintext: ', plaintext)
        return plaintext

def main():
    cipher = StrangeCBC(get_random_bytes(16))

    # print('first')
    # # Block-aligned pts
    # for pt in [bytes(range(i)) for i in range(0, 256, 16)]:
    #     assert cipher.decrypt(cipher.encrypt(pt)) == pt
    # # print('second')
    # # # Non-block-aligned pts
    # for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
    #     assert cipher.decrypt(cipher.encrypt(pt)) == pt

    key = bytes.fromhex("5f697180e158141c4e4bdcdc897c549a")
    iv  = bytes.fromhex("89c0d7fef96a38b051cb7ef8203dee1f")
    ct = bytes.fromhex(
            "e7fb4360a175ea07a2d11c4baa8e058d57f52def4c9c5ab"
            "91d7097a065d41a6e527db4f5722e139e8afdcf2b229588"
            "3fd46234ff7b62ad365d1db13bb249721b")
    pt = StrangeCBC(key, iv=iv).decrypt(ct)
    print(pt.decode())
    print("flag{" + SHA1.new(pt).digest().hex() + "}")

if __name__ == "__main__":
    main()
