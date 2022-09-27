#--------------------------------------------------------------------------#
# Joshua von Damm
# CSC321 Lab 1
#--------------------------------------------------------------------------#

import sys
from Crypto.Cipher import AES
from os import urandom
from bitstring import BitArray

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

def part1():
    if len(sys.argv) == 0 or len(sys.argv) > 3:
        print("USAGE: python3 crypto.py 1 <plaintext file>")
        exit(0)

    
    with open(sys.argv[2], 'rb') as file:
        header = file.read(54)
        data = file.read()

    key = urandom(16)
    curVector = urandom(16)
    ecb = AES.new(key, AES.MODE_ECB)

    ecbMsg = bytearray()
    cbcMsg = bytearray()

    # TODO ecb and cbc output the same thing
    for i in range(0, len(data), AES_LEN):
        cbc = AES.new(key, AES.MODE_ECB, curVector) 
        block = data[i:i+AES_LEN]
        block = pad(block)
        ecbMsg += ecb.encrypt(block)
        curVector = cbc.encrypt(block)
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

def submit(key, initVector):
    userdata = input("Enter some data: ")
    url = "userid=456;userdata=" + userdata + ";session-id=31337"
    cbc = AES.new(key, AES.MODE_ECB, initVector)
    return cbc.encrypt(url)

if __name__ == "__main__":
    main()