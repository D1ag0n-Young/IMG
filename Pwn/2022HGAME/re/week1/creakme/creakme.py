from ctypes import *

def dec(v,k):
    for i in range(0,8,2):
        v0 = c_uint32(v[i]& 0xffffffff)
        v1 = c_uint32(v[i + 1]& 0xffffffff)
        v7 = 32;
        v3 = c_uint32((0x12345678 * 32)& 0xffffffff) 

        print(i,hex(v3.value))
        while ( v7 ):
            v1.value -= (v3.value ^ (v3.value + v0.value) ^ (k[0] + v0.value*16) ^ (k[1] + (v0.value >> 5)))
            v0.value -= (v3.value ^ (v3.value + v1.value) ^ (k[2] + v1.value*16) ^ (k[3] + (v1.value >> 5)))
            v3.value -= 0x12345678
            print(hex(v1.value))
            v7 -= 1
        v3.value = 0
        v[i] = v0.value&0xffffffff
        v[i + 1] = v1.value& 0xffffffff
    return v

# v = [0xED9CE5ED52EB78C2030C144C48D93488,0x65E0F2E3CF9284AABA5A126DAE1FEDE6,,,]
v = [0x48D93488,0x030C144C,0x52EB78C2,0xED9CE5ED,0xAE1FEDE6,0xBA5A126D,0xCF9284AA,0x65E0F2E3]
# k = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
k = [0x44434241,0x48474645,0x4c4b4a49,0x504f4e4d]

flaglist = dec(v,k)
# flaglist = [0x6d616768,0x34487b65,0x5f797070,0x34633476,0x6e306974,0x7d21]

# # WOW 
# flagwow = [0x6D616768,0x4F577B65,0x5F574F57,0x70704068,0x336E5F79,0x65795F77,0x325F7234,0x7D323230]
print (flaglist)
for i in flaglist:
    print (chr(i&0xff),end='')
    print (chr(i>>8&0xff),end='')
    print (chr(i>>16&0xff),end='')
    print (chr(i>>24&0xff),end='')
    print (chr(i>>32&0xff),end='')
# 注意python和c的区别，当有溢出时 <<4 并不等于 *16

