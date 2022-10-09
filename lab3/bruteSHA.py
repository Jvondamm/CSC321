from itertools import product
import hashlib
import timeit

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
    part4B()

if __name__ == "__main__":
    main()