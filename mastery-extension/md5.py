import hashlib
from nltk.corpus import words
import timeit
from itertools import product

def main():
    strings = words.words()
    print("Number of words: ", len(strings))

    count = 0
    length = 1
    hashes = {}
    m = ''
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*?,()-=+[]/;"
    start = timeit.default_timer()

    while True:
        for a in product(chars, repeat=length):
            if (count % 1000000 == 0):
                print(count, timeit.default_timer()-start)
            msg = m.join(a)
            hash = hashlib.md5(msg.encode()).hexdigest()
            count += 1
            if hash in hashes:
                stop = timeit.default_timer()
                print("Collision found.\n \
                Word 1: %s\n" % hashes[hash],
                "Word 2: %s\n" % msg,
                "Hash: %s\n" % hash,
                "Time to brute: %s\n" % str(stop-start),
                "Hashes Attempted: %s" % str(count))
                exit(0)
            else:
                hashes[hash] = msg
        length += 1

if __name__ == '__main__':
        main()