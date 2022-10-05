from hashlib import sha256
from itertools import product
from timeit import default_timer
from numba import jit

@jit
def brute_force(hashed, input):
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    length = 1
    count = 0
    m = ''
    while True:
        for a in product(chars, repeat=length):
            msg = m.join(a)
            if msg != input:
                if sha256(msg.encode()).hexdigest()[:2] == hashed:
                    return msg, hashed, count
                count += 1
        length += 1
        if length == 20:
            return None

start = default_timer()
input = "cat"
hashed1 = sha256(str(input).encode()).hexdigest()[:2]
print((input, hashed1))
print(brute_force(hashed1, input))
stop = default_timer()
print('Time: ', stop - start)