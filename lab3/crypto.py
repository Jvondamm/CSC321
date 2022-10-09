#--------------------------------------------------------------------------#
# Joshua von Damm
# CSC321 Lab 3
#--------------------------------------------------------------------------#

from Crypto.Cipher import AES
from Crypto.Util import number
import random
import hashlib
from itertools import product
from os import urandom
import difflib
import timeit

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

P = int.from_bytes(bytes(P, 'utf-8'), "big")
G = int.from_bytes(bytes(G, 'utf-8'), "big")

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
    cbc = AES.new(kAlice[:16].encode("utf8"), AES.MODE_ECB)

    mAlice = bytes("Hi Bob!", 'utf-8')
    mBob = bytes("Hi Alice!", 'utf-8')

    eAlice = encrypt(mAlice, cbc, curVector)
    eBob = encrypt(mBob, cbc, curVector)

    mFinalBob = decrypt(eBob, cbc, curVector)
    mFinalAlice = decrypt(eAlice, cbc, curVector)

    print(mFinalAlice, mFinalBob)

def part2A():

    aAlice = random.randint(1, P - 1)
    bBob = random.randint(1, P - 1)

    aMallory = random.randint(1, P - 1)
    bMallory = random.randint(1, P - 1)

    # Alice and Bob make their A and B, but Mallory intercepts and they are never used
    AAlice = pow(G, aAlice, P)
    BBob = pow(G, bBob, P)

    # Mallory computes her own A and B for Alice and Bob
    AMallory = pow(G, aMallory, P)
    BMallory = pow(G, bMallory, P)

    # Mallory sends her own A and B to Alice and Bob
    sAlice = pow(BMallory, aAlice, P)
    sBob = pow(AMallory, bBob, P)

    kAlice = hashlib.sha256(str(sAlice).encode()).hexdigest()
    kBob = hashlib.sha256(str(sBob).encode()).hexdigest()

    print("Alice and Bob keys match: " + str(kAlice == kBob))

    curVector = urandom(16)

    # Alice and Bob create their ciphers thinking they are making the same one.
    # Mallory does the same for both their ciphers
    cbcAlice = AES.new(kAlice[:16].encode("utf8"), AES.MODE_ECB)
    cbcBob  = AES.new(kBob[:16].encode("utf8"), AES.MODE_ECB)

    mAlice = bytes("Hi Bob!", 'utf-8')
    mBob = bytes("Hi Alice!", 'utf-8')

    # Alice encrypts to send to Bob
    eAlice = encrypt(mAlice, cbcAlice, curVector)
    # Bob encrypts to send to Alice
    eBob = encrypt(mBob, cbcBob, curVector)

    # Mallory intercepts, decrypts using their respective keys
    middleAlice = decrypt(eBob, cbcBob, curVector)
    middleBob = decrypt(eAlice, cbcAlice, curVector)

    print("Mallory seeks the messages:" )
    print(middleAlice, middleBob)

    # Mallory encrypts with the other keys
    eMalloryAlice = encrypt(middleAlice, cbcBob, curVector)
    eMalloryBob = encrypt(middleBob, cbcAlice, curVector)

    mFinalAlice = decrypt(eMalloryAlice, cbcBob, curVector)
    mFinalBob = decrypt(eMalloryBob, cbcAlice, curVector)

    # Bob and Alice receive and decrypt their messages, thinking everything is fine
    print("What Alive and Bob receive:")
    print(mFinalAlice, mFinalBob)

def part2B():

    G = 1

    aAlice = random.randint(1, P - 1)
    bBob = random.randint(1, P - 1)

    AAlice = pow(G, aAlice, P)
    BBob = pow(G, bBob, P)

    # Mallory knows AAlive and BBob are 1 which makes sAlice and sBob 1.
    sAlice = pow(BBob, aAlice, P)
    sBob = pow(AAlice, bBob, P)

    print(sAlice, sBob)

    kAlice = hashlib.sha256(str(sAlice).encode()).hexdigest()
    kBob = hashlib.sha256(str(sBob).encode()).hexdigest()

    # Mallory knows the value is 1 and encodes the same secret
    kMallory = hashlib.sha256(str(1).encode()).hexdigest()

    print("Alice and Bob keys match: " + str(kAlice == kBob))

    print("Alice and Bob keys match Mallory's: " + str(kAlice == kBob == kMallory))

    curVector = urandom(16)
    cbc = AES.new(kAlice[:16].encode("utf8"), AES.MODE_ECB)

    # Mallory can then duplicate Alice and Bob's deterministic cipher
    cbcMallory = AES.new(kMallory[:16].encode("utf8"), AES.MODE_ECB)

    mAlice = bytes("Hi Bob!", 'utf-8')
    mBob = bytes("Hi Alice!", 'utf-8')

    eAlice = encrypt(mAlice, cbc, curVector)
    eBob = encrypt(mBob, cbc, curVector)

    # Mallory can now decrypt the messages she intercepts
    mAMallory = decrypt(eAlice, cbcMallory, curVector)
    mBMallory = decrypt(eBob, cbcMallory, curVector)
    print("Mallory's decrypted intercepted messages from Alice and Bob:")
    print(mAMallory, mBMallory)

    mFinalBob = decrypt(eBob, cbc, curVector)
    mFinalAlice = decrypt(eAlice, cbc, curVector)

    print("Alice and Bob's messages to each other they think are secret:")
    print(mFinalAlice, mFinalBob)

# Source: https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm
def inverse(a, n):
    t = 0
    r = n
    newr = a
    newt = 1

    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr

    if r > 1:
        return None
    if t < 0:
        t = t + n
    return t

def keyGen():
    e = 65537
    plen = 2048
    a = number.getPrime(plen, randfunc=None)
    b = number.getPrime(plen, randfunc=None)

    n = a * b
    phi = (a-1) * (b-1)

    d = inverse(e, phi)

    return((e, n), (d, n))

def part3A():
    (pub, n), (priv, n) = keyGen()
    print((pub, n), (priv, n))

    plain = 100

    cipher =  pow(plain, pub, n)

    final = pow(cipher, priv, n)

    print(final)

def part3B():

    # Alice gens keys
    (pub, n), (priv, n) = keyGen()

    # Alice sends to Bob, Mallory listens and now knows pubkey and a.

    # Bob creates message
    plain = 100

    # Bob encrypts message and sends
    cipher =  pow(plain, pub, n)

    # Mallory listens and literally doesn't care, sends cipher value of 1
    cipher = 1

    # Alice receives message and decrypts
    final = pow(cipher, priv, n)

    # Alice creates symmetric key
    k = hashlib.sha256(final.to_bytes(1, byteorder='big')).hexdigest()
    m = "Hi Bob!"
    print("Alice plans to send secret message: ", m)
    m = bytes(m, 'utf-8')

    curVector = urandom(16)
    cbc = AES.new(k[:16].encode("utf8"), AES.MODE_ECB)

    # Mallory knows what the key will be and makes a copy of the AES encryption
    i = 1
    kMallory = hashlib.sha256(i.to_bytes(1, byteorder='big')).hexdigest()
    cbcMallory = AES.new(kMallory[:16].encode("utf8"), AES.MODE_ECB)

    # Alice encrypts her message and sends
    ciphertext = encrypt(m, cbc, curVector)

    # Mallory intercepts and decrypts the secret message
    plaintext = decrypt(ciphertext, cbcMallory, curVector)
    print("Mallory decrypts: ", plaintext)


def part4A():
    step = 4
    input1 = b"0000000110001"
    input2 = b"0000000110000"
    hashed1 = int(hashlib.sha256(str(input1).encode()).hexdigest(), 16) & (pow(2, step)-1)
    hashed2 = int(hashlib.sha256(str(input2).encode()).hexdigest(), 16) & (pow(2, step)-1)
    print(hashed1, hashed2)

def bday(chars, step):
    count = 0
    length = 1
    hashes = {}
    m = ''
    start = timeit.default_timer()
    while True:
        for a in product(chars, repeat=length):
            msg = m.join(a)
            hash = int(hashlib.sha256(msg.encode()).hexdigest(), 16) & (pow(2, step)-1)
            count += 1
            if hash in hashes:
                stop = timeit.default_timer()
                print("M1: ", hashes[hash], "M2: ", msg, "Hash: ", hash)
                print("Time to break: ", stop-start, "Hashes attempted: ", count, "\n")
                return
            else:
                hashes[hash] = msg
        length += 1

def part4B():
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    for step in range(2, 52, 2):
        print("Breaking bit length of ", step)
        bday(chars, step)

def main():
    part1()

if __name__ == "__main__":
    main()