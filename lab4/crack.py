from nltk.corpus import words
import bcrypt
import timeit

words = words.words()
words = [word for word in words if (len(word) >= 6 and len(word) <= 8)]
print("Number of words: ", len(words))

passwords = {}
with open('shadow_file.txt') as f:
    for line in f:
        password = line.split(":")[1].strip().encode('utf-8')
        salt = line.split(":")[1][:29].encode('utf-8')
        if salt in passwords:
            passwords[salt].append(password)
        else:
            passwords[salt] = [password]

counter = 0
start = timeit.default_timer()

for word in words:
    if counter % 60 == 0:
        print(counter)
    for salt in passwords:
        hashed = bcrypt.hashpw(word.encode('utf-8'), salt)
        for password in passwords[salt]:
            counter += 1
            if hashed == password:
                passwords[salt].remove(password)
                stop = timeit.default_timer()
                print("Cracked password is: ", word, " Time to crack: ", stop-start)
                start = timeit.default_timer()

# for word in words:
#     if counter % 15 == 0:
#         print(counter)
#     for i in range(0, len(passwords)):
#         counter += 1
#         if bcrypt.checkpw(word.encode('utf-8'), passwords[i]):
#             print("Cracked password is: ", word)