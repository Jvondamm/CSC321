import base64
import sys
import hashlib
from Crypto.Cipher import AES
from os import urandom

AES_LEN = 16

def main():
    if len(sys.argv) == 0 or len(sys.argv) > 2:
        print("USAGE: python3 crypto.py <plaintext file>")
        exit(0)

    with open(sys.argv[1], 'r') as file:
        data = file.read().rstrip()

    key = urandom(16)
    initVector = urandom(16)
    ecb = AES.new(key, AES.MODE_ECB)
    cbc = AES.new(key, AES.MODE_ECB, initVector)

    ecbMsg = ""
    cbcMsg = ""

    for i in (0, len(data), AES_LEN):
        block = data[i:i+AES_LEN]
        if (i + AES_LEN) > len(data):
            lenNeeded = len(data) % AES_LEN
            str = str(lenNeeded).zfill(2)
            block += str * lenNeeded

        print(len(block), block)
        ecbMsg += ecb.encrypt(block).hex()
        # hex them to be readable
        cbcMsg += cbc.encrypt(block).hex()

        print(ecbMsg, cbcMsg)

    print("ECB: %" % ecbMsg)
    print("CBC: %" % cbcMsg)


if __name__ == "__main__":
    main()