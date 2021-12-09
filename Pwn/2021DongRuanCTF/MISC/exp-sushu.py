# coding = utf-8
################################
# Withinlover
# 2020.11.2
################################

from random import randint
import time

def miller_rabin(p):
    if p == 1: return False
    if p == 2: return True
    if p % 2 == 0: return False
    m, k, = p - 1, 0
    while m % 2 == 0:
        m, k = m // 2, k + 1
    a = randint(2, p - 1)
    x = pow(a, m, p)
    if x == 1 or x == p - 1: return True
    while k > 1:
        x = pow(x, 2, p)
        if x == 1: return False
        if x == p - 1: return True
        k = k - 1
    return False

def is_prime(p, r = 40):
    for i in range(r):
        if miller_rabin(p) == False:
            return False
    return True

if __name__ == '__main__':
    T = time.perf_counter()
    for _ in range(100):
        index = 1024
        print(index, "prime: ", end="")
        num = 0
        for i in range(index):
            num = num * 2 + randint(0, 1)
        while is_prime(num) == False:
            num = num + 1
        print(num)
        print("----------------------------")
    print("用时：", time.perf_counter() - T)
