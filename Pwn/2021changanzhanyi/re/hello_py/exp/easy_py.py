# uncompyle6 version 3.7.4
# Python bytecode 3.8 (3413)
# Decompiled from: Python 2.7.18 (default, Mar  8 2021, 13:02:45) 
# [GCC 9.3.0]
# Warning: this version of Python has problems handling the Python 3 "byte" type in constants properly.

# Embedded file name: C:\Users\Administrator\Desktop\easy_py.py
# Compiled at: 2021-12-28 15:45:17
# Size of source mod 2**32: 1099 bytes
import threading, time

def encode_1(n):
    global num
    while True:
        if num >= 0:
            flag[num] = flag[num] ^ num
            num -= 1
            time.sleep(1)
        if num <= 0:
            break


def encode_2(n):
    global num
    while True:
        if num >= 0:
            flag[num] = flag[num] ^ flag[(num + 1)]
            num -= 1
            time.sleep(1)
        if num < 0:
            break


while True:
    Happy = [
     44, 100, 3, 50, 106, 90, 5, 102, 10, 112]
    num = 9
    f = input('Please input your flag:')
    if len(f) != 10:
        print('Your input is illegal')
    else:
        flag = list(f)
        j = 0
        for i in flag:
            flag[j] = ord(i)
            j += 1
        else:
            print("flag to 'ord':", flag)
            t1 = threading.Thread(target=encode_1, args=(1, ))
            t2 = threading.Thread(target=encode_2, args=(2, ))
            t1.start()
            time.sleep(0.5)
            t2.start()
            t1.join()
            t2.join()

        if flag == Happy:
            print('Good job!')
        else:
            print('No no no!')
# okay decompiling easy_py.cpython-38.pyc
