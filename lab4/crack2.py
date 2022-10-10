from nltk.corpus import words
from multiprocessing import Pool, freeze_support
from functools import partial
import bcrypt
import timeit

def loop(passwords, start, word):
    for password in passwords:
        if bcrypt.checkpw(word.encode('utf-8'), password):
            print("Cracked password is: ", word, " for hash: ", password, " Time to crack: ", timeit.default_timer()-start)

def main():
    strings = words.words()
    strings = [word for word in strings if (len(word) >= 6 and len(word) <= 8)]
    print("Number of words: ", len(strings))

    passwords = {}
    with open('shadow_file.txt') as f:
        for line in f:
            password = line.split(":")[1].strip().encode('utf-8')
            salt = line.split(":")[1][:29].encode('utf-8')
            if salt in passwords:
                passwords[salt].append(password)
            else:
                passwords[salt] = [password]
    start = timeit.default_timer()

    pool = Pool()
    pool.map(partial(loop, passwords, start), strings)
    pool.close()
    pool.join()


if __name__=="__main__":
    freeze_support()
    main()