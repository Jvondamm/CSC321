from nltk.corpus import words
import bcrypt
import timeit

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

    for word in words:
        for password in passwords:
            if bcrypt.checkpw(word.encode('utf-8'), password):
                print("Cracked password is: ", word, " for hash: ", password, " Time to crack: ", timeit.default_timer()-start)

if __name__=="__main__":
    main()