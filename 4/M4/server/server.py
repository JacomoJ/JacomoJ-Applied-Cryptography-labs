import secrets
from boilerplate import CommandServer, on_command

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE = 16

def blockify(a):
    return [a[i : i + BLOCK_SIZE] for i in range(0, len(a), BLOCK_SIZE)]

class CBCServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.key = secrets.token_bytes(16)
        super().__init__(*args, **kwargs)

    @on_command("decrypt")
    def handle_encrypt(self, msg):
        self.send_message(
            {"error": "Sorry, we haven't implemented encryption... uh, decryption yet"}
        )

    @on_command("encrypt")
    def handle_decrypt(self, msg):
        try:
            file_name = msg["file_name"].encode()
            data = bytes.fromhex(msg["data"])

            ptxt = (
                b"filename="
                + file_name
                + b"&data="
                + data
                + b"&flag="
                + self.flag.encode()
            )

            iv = secrets.token_bytes(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
            ptxt_pad = pad(ptxt, AES.block_size)
            print('ptxt_pad: ', blockify(ptxt_pad))
            ctxt = cipher.decrypt(ptxt_pad)
            print('len ctxt: ', len(blockify(ctxt)))
            self.send_message({"iv": iv.hex(), "ctxt": ctxt.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})


if __name__ == "__main__":
    flag = "flag{loooong_loooooong_test_flag}"
    len(flag)
    CBCServer.start_server("0.0.0.0", 50404, flag=flag)
