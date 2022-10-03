#--------------------------------------------------------------------------#
# Joshua von Damm
# CSC321 Lab 3
#--------------------------------------------------------------------------#


from Crypto.Cipher import AES
import random
import hashlib
from os import urandom

AES_LEN = 16
P = "B10B8F96A080E01DDE92DE5EAE5D54EC\
    52C99FBCFB06A3C69A6A9DCA52D23B616073E2\
    8675A23D189838EF1E2EE652C013ECB4AEA9061\
    12324975C3CD49B83BFACCBDD7D90C4BD7098488\
    E9C219A73724EFFD6FAE5644738FAA31A4FF55BCC\
    C0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA7\
    6D4DA708DF1FB2BC2E4A4371"
G = "A4D1CBD5C3FD34126765A442EFB99905F8104DD25\
    8AC507FD6406CFF14266D31266FEA1E5C41564B777E690F\
    5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3\
    B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A016\
    9B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97\
    C2A24855E6EEB22B3B2E5"

P.join(str(ord(c)) for c in P)
G.join(str(ord(c)) for c in G)

P = (P, 'utf-8')
G = (G, 'utf-8')

def xor(arr1, arr2):
    return bytes(a ^ b for (a, b) in zip(arr1, arr2))

def pad(m):
    return m + bytes(chr(AES_LEN-len(m)%AES_LEN)*(AES_LEN-len(m)%AES_LEN), 'utf-8')

def unpad(m):
    return m[:-ord(m[len(m)-1:])]

def encrypt(data, cbc, curVector):
    cbcMsg = bytearray()

    for i in range(0, len(data), AES_LEN):
        block = data[i:i+AES_LEN]
        ecbBlock = pad(block)
        cbcBlock = xor(ecbBlock, curVector)
        curVector = cbc.encrypt(cbcBlock)
        cbcMsg += curVector

    return cbcMsg

def decrypt(data, cbc, curVector):
    plaintext = bytearray()

    for i in range(0, len(data), AES_LEN):
        block = data[i:i+AES_LEN]
        msg = cbc.decrypt(bytes(block))
        plaintext += xor(msg, curVector)
        curVector = block

    return(unpad(bytes(plaintext)))

def part1():

    aAlice = random.randint(1, P - 1)
    bBob = random.randint(1, P - 1)

    AAlice = pow(G, aAlice, P)
    BBob = pow(G, bBob, P)

    sAlice = pow(BBob, aAlice, P)
    sBob = pow(AAlice, bBob, P)

    kAlice = hashlib.sha256(str(sAlice).encode()).hexdigest()
    kBob = hashlib.sha256(str(sBob).encode()).hexdigest()

    print("Alice and Bob keys match: " + str(kAlice == kBob))

    curVector = urandom(16)
    cbc = AES.new(kAlice[:16], AES.MODE_ECB)

    mAlice = bytes("Hi Bob!", 'utf-8')
    mBob = bytes("Hi Alice!", 'utf-8')

    eAlice = encrypt(mAlice, cbc, curVector)
    eBob = encrypt(mBob, cbc, curVector)

    mFinalAlice = decrypt(eBob, cbc, curVector)
    mFinalBob = decrypt(eAlice, cbc, curVector)

    print(mFinalAlice, mFinalBob)

def main():
    part1()

if __name__ == "__main__":
    main()