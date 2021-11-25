#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "chacha20.h"

static inline void u32t8le(uint32_t v, uint8_t p[4]) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;
    p[2] = (v >> 16) & 0xff;
    p[3] = (v >> 24) & 0xff;
}

static inline uint32_t u8t32le(uint8_t p[4]) {
    uint32_t value = p[3];

    value = (value << 8) | p[2];
    value = (value << 8) | p[1];
    value = (value << 8) | p[0];

    return value;
}

static inline uint32_t rotl32(uint32_t x, int n) {
    // http://blog.regehr.org/archives/1063
    return x << n | (x >> (-n & 31));
}

// https://tools.ietf.org/html/rfc7539#section-2.1
static void chacha20_quarterround(uint32_t* x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 8);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 7);
}

static void chacha20_serialize(uint32_t in[16], uint8_t output[64]) {
    int i;
    for (i = 0; i < 16; i++) {
        u32t8le(in[i], output + (i << 2));
    }
}

static void chacha20_block(uint32_t in[16], uint8_t out[64], int num_rounds) {
    int i;
    uint32_t x[16];

    memcpy(x, in, sizeof(uint32_t) * 16);

    for (i = num_rounds; i > 0; i -= 2) {
        chacha20_quarterround(x, 0, 4, 8, 12);
        chacha20_quarterround(x, 1, 5, 9, 13);
        chacha20_quarterround(x, 2, 6, 10, 14);
        chacha20_quarterround(x, 3, 7, 11, 15);
        chacha20_quarterround(x, 0, 5, 10, 15);
        chacha20_quarterround(x, 1, 6, 11, 12);
        chacha20_quarterround(x, 2, 7, 8, 13);
        chacha20_quarterround(x, 3, 4, 9, 14);
    }

    for (i = 0; i < 16; i++) {
        x[i] += in[i];
    }

    chacha20_serialize(x, out);
}

// https://tools.ietf.org/html/rfc7539#section-2.3
static void chacha20_init_state(uint32_t s[16], uint8_t key[32], uint32_t counter, uint8_t nonce[12]) {
    int i;

    // refer: https://dxr.mozilla.org/mozilla-beta/source/security/nss/lib/freebl/chacha20.c
    // convert magic number to string: "expand 32-byte k"
    s[0] = 0x61707865;
    s[1] = 0x3320646e;
    s[2] = 0x79622d32;
    s[3] = 0x6b206574;

    for (i = 0; i < 8; i++) {
        s[4 + i] = u8t32le(key + i * 4);
    }

    //s[12] = counter;

    //for (i = 0; i < 3; i++) {
    //    s[13 + i] = u8t32le(nonce + i * 4);
    //}
}

void ChaCha20XOR(uint8_t key[32], uint32_t counter, uint8_t nonce[12], uint8_t* in, uint8_t* out, int inlen) {
    int i, j;

    uint32_t s[16];
    uint8_t block[64];

    chacha20_init_state(s, key, counter, nonce);//暂时不用
    uint32_t stmp[16] = {
        0x61707865,0x3320646e,0x79622d32,0x6b206574,
        0x40334e30,0x5f495961,0x306c334d,0x4b5f7964,
        0x6d4f7275,0x5f575f31,0x316b7553,0x30797164,
        0x00000000,0x00000000,0x69746f64,0x74697374
    };
    memcpy(s, stmp, 64); //直接初始化
    printf("%08x", s);
    for (i = 0; i < inlen; i += 64) {
        chacha20_block(s, block, 20);
        s[12]++;

        for (j = i; j < i + 64; j++) {
            if (j >= inlen) {
                break;
            }
            out[j] = in[j] ^ block[j - i];
        }
    }
}



#include <stdio.h>  
#include <stdint.h>  
#define DELTA 0x9e3779b9  
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))  

void btea(uint32_t* v, int n, uint32_t const key[4])
{
    uint32_t y, z, sum;
    unsigned p, rounds, e;
    if (n > 1)            /* Coding Part */
    {
        rounds = 6 + 52 / n;
        sum = 0;
        z = v[n - 1];
        do
        {
            sum += DELTA;
            e = (sum >> 2) & 3;
            for (p = 0; p < n - 1; p++)
            {
                y = v[p + 1];
                z = v[p] += MX;
            }
            y = v[0];
            z = v[n - 1] += MX;
        } while (--rounds);
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52 / n;
        sum = rounds * DELTA;
        y = v[0];
        do
        {
            e = (sum >> 2) & 3;
            for (p = n - 1; p > 0; p--)
            {
                z = v[p - 1];
                y = v[p] -= MX;
            }
            z = v[n - 1];
            y = v[0] -= MX;
            sum -= DELTA;
        } while (--rounds);
    }
}
char* uitoa(unsigned int n, char* s)
{
    int i, j;
    i = 0;
    char buf[20];
    memset(buf, 0, sizeof(buf));
    do {
        buf[i++] = n &0xff;//取下一个数字
    } while ((n >>=8) > 0);//删除该数字   
    i -= 1;
    for (j = 0; i >= 0; j++, i--)//生成的数字是逆序的，所以要逆序输出
        s[j] = buf[j];
    s[j] = '\0';
    return s;
}
int firstkey_xxtea()
{
    uint32_t v[2] = { 0x1130BE1B,0x63747443 }; //v5:v3
    char s[8] = {0};
    //uint32_t v[2] = { 0x69746f64,0x74697374 };
    //v5 == 0x1130BE1B && v3 == 0x63747443
    /*
    * v13[0] = 114;
      v13[1] = 514;
      v13[2] = 19;
      v13[3] = 19;
    */
    uint32_t const k[4] = { 114,514,19,19 };
    int n = 2; //n的绝对值表示v的长度，取正表示加密，取负表示解密  
    // v为要加密的数据是两个32位无符号整数  
    // k为加密解密密钥，为4个32位无符号整数，即密钥长度为128位  
    printf("加密前原始数据：%x %x\n", v[0], v[1]);
    btea(v, -n, k);
    printf("加密后的数据：%x %x\n", v[0], v[1]);

    //btea(v, -n, k);
    //printf("解密后的数据：%x %x\n", v[0], v[1]);
    printf("s1 = %s\n", uitoa(v[0],s));
    printf("s1 = %s\n", uitoa(v[1],s));
    return 0;
}


int main(int argc, char** argv) {
    firstkey_xxtea();
    int i;

    uint8_t key[] = { //32byte key
        48,78,51,64,97,89,73,95,
        77,51,108,48,100,121,95,75,
        117,114,79,109,49,95,87,95,
        83,117,107,49,100,113,121,48
    };

    uint8_t nonce[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t enc[32] = { //encrypt data
          0xEB, 0x8E, 0x5C, 0xA5, 0x62, 0xB4, 0x1C, 0x84, 0x5C, 0x59,
          0xFC, 0x0D, 0x43, 0x3C, 0xAB, 0x20, 0xD8, 0x93, 0x33, 0x13,
          0xA1, 0x9E, 0x39, 0x00, 0x76, 0x14, 0xB5, 0x04, 0x58, 0x9D,
          0x06, 0xB8
    };

    //uint8_t encrypt[32];
    uint8_t decrypt[32];

    ChaCha20XOR(key, 1, nonce, enc, decrypt, 32);
    // ChaCha20XOR(key, 1, nonce, encrypt, decrypt, 114);

    printf("\nkey:");
    for (i = 0; i < 32; i++) {
        if (!(i % 16)) {
            printf("\n");
        }
        printf("%02x ", key[i]);
    }

    printf("\n\nencrypted:");
    for (i = 0; i < 32; i++) {
        if (!(i % 16)) {
            printf("\n");
        }
        printf("%02x ", enc[i]);
    }

    printf("\n\ndecrypted:");
    for (i = 0; i < 32; i++) {
        if (!(i % 16)) {
            printf("\n");
        }
        printf("%02x ", decrypt[i]);
    }
    printf("\n%.32s", decrypt);
    printf("\n");
    return 0;
}