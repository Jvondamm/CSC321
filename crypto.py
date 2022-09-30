#--------------------------------------------------------------------------#
# Joshua von Damm
# CSC321 Lab 1
#--------------------------------------------------------------------------#

from pydoc import plain
import sys
from Crypto.Cipher import AES
from os import urandom

AES_LEN = 16

def main():
    if len(sys.argv) <= 1:
        print("USAGE: python3 crypto.py 1-3 <optional file input>")
        exit(0)

    if sys.argv[1] == "1":
        part1()
    elif sys.argv[1] == "2":
        part2()
    elif sys.argv[1] == "2":
        pass
    else:
        print("Arg out of bounds")
        exit(0)

def pad(m):
    return m + bytes(chr(AES_LEN-len(m)%AES_LEN)*(AES_LEN-len(m)%AES_LEN), 'utf-8')

def unpad(m):
    return m[:-ord(m[len(m)-1:])]

def xor(arr1, arr2):
    return bytes(a ^ b for (a, b) in zip(arr1, arr2))

def part1():
    if len(sys.argv) <=1 or len(sys.argv) > 3:
        print("USAGE: python3 crypto.py 1 <plaintext file>")
        exit(0)


    with open(sys.argv[2], 'rb') as file:
        header = file.read(54)
        data = file.read()

    key = urandom(16)
    curVector = urandom(16)
    ecb = AES.new(key, AES.MODE_ECB)
    cbc = AES.new(key, AES.MODE_ECB)

    ecbMsg = bytearray()
    cbcMsg = bytearray()

    # TODO ecb and cbc output the same thing
    for i in range(0, len(data), AES_LEN):
        block = data[i:i+AES_LEN]
        ecbBlock = pad(block)
        cbcBlock = xor(ecbBlock, curVector)
        ecbMsg += ecb.encrypt(ecbBlock)
        curVector = cbc.encrypt(cbcBlock)
        cbcMsg += curVector

    ecb_file = open("ecb.bmp", 'wb')
    cbc_file = open("cbc.bmp", 'wb')
    ecb_file.write(header + ecbMsg)
    cbc_file.write(header + cbcMsg)
    ecb_file.close()
    cbc_file.close()

def part2():
    key = urandom(16)
    initVector = urandom(16)

    ciphertext = submit(key, initVector)
    # TODO I know that I need to flip two bytes, and think it is the 17th adn 22nd spot which will flip single bits in the following block.
    # I know the ascii values: ; is 59, =  is 61.
    # my ciphertext is a bytearray
    # I have no clue how to flip the bits.
    # I have tried so many implementations to no avail.
    ciphertext[18] = 59 ^ ciphertext[18 + 16]
    ciphertext[24] = 61 ^ ciphertext[24 + 16]
    print(ciphertext[18 + 16], ciphertext[18])

    verify(ciphertext, key, initVector)

def submit(key, initVector):
    userdata = input("Enter some data: ")

    url = bytes("userid=456;userdata=" +
            userdata.replace("=", "%3D").replace(";", "%3B")
            + ";session-id=31337", 'utf-8')

    cbc = AES.new(key, AES.MODE_ECB)
    cbcMsg = bytearray()
    curVector = initVector
    url = pad(url)
    for i in range(0, len(url), AES_LEN):
        block = xor(url[i:i+AES_LEN], curVector)
        curVector = cbc.encrypt(block)
        cbcMsg += curVector
    return cbcMsg

def verify(ciphertext, key, curVector):
    cbc = AES.new(key, AES.MODE_ECB)
    plaintext = bytearray()

    for i in range(0, len(ciphertext), AES_LEN):
        block = ciphertext[i:i+AES_LEN]
        msg = cbc.decrypt(bytes(block))
        if i == 32:
            print(msg[2], curVector[2])
        plaintext += xor(msg, curVector)
        curVector = block

    finaltext = unpad(bytes(plaintext))
    print(finaltext)
    if ";admin=true" in str(finaltext):
        return True
    else:
        return False

if __name__ == "__main__":
    main()