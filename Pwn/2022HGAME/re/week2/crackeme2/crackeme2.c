#include<stdio.h>
#include <stdint.h> 
int main(int argc, const char** argv, const char** envp)
{
    int v3; // edx
    int i; // esi
    unsigned int v0; // edi
    unsigned int v1; // ebx
    int v7; // esi
    int v8; // esi
    int v13; // [esp+90h] [ebp-8h]
    int v14; // [esp+94h] [ebp-4h]

    //65E0F2E3CF9284AABA5A126DAE1FEDE6 ED9CE5ED52EB78C2030C144C48D93488
#if 1
    uint32_t  ida_chars[8] =
    { 
     0x457E62CF, 0x9537896C,0x1F7E7F72,0xF7A073D8,0x8E996868,0x40AFAF99, 0x0F990E34, 0x196F4086
     //0x196F4086,0x0F990E34,0x40AFAF99,0x8E996868,0x0F7A073D8,0x1F7E7F72,0x9537896C, 0x457E62CF
        
    };
#endif
#if 0
     uint32_t  ida_chars[8] =
    {
        0x31313131,0x31313131,0x31313131,0x31313131,0x31313131,0x31313131,0x31313131,0x31313131
        //0x8EFD25F5, 0x0ADBCBA4F, 0x8EFD25F5, 0x0ADBCBA4F, 0x8EFD25F5,0x0ADBCBA4F,0x8EFD25F5,0x0ADBCBA4F
    };
 #endif
    uint32_t k[10] =
    { 0x1, 0x2, 0x3, 0x4,0x5, 0x6, 0x7, 0x8,0x9,0x0
    };
    v3 = 0;
    v14 = 0;
    for (i = 0; i < 8; v14 = i)
    {
        v0 = ida_chars[i];
        v1 = ida_chars[i + 1];
        v13 = 0;
        v7 = 32;
#if 1
        v3 = 0xc78e4d05 & 0xffffffff;
        //printf("%x\n", v3);
        for (int j = 0; j < 32; ++j) {
            v1 -= (v3 + k[((v3 >> 11) | 0xffe00000) & 3]) ^ (v0 + ((v0 << 4) ^ (v0 >> 5)));
            uint32_t ss;
            ss = (v3 >> 0x1f);
            if (!ss) {
                v3 ^= 0x1234567;
            }
            v3 -= 0x9E3779B1;

            v0 -= (v3 + k[v3 & 3]) ^ (v1 + ((v1 << 4) ^ (v1 >> 5)));
            //  printf("%x\n", v1);
        }

#endif // 0
#if 0
        do
        {
            v0 += (v3 + k[v3 & 3]) ^ (v1 + (( v1<<4) ^ (v1 >> 5)));
            v3 += 0x9E3779B1;
            uint32_t ss;
            ss = (v3 >> 0x1f);
            if (!ss) {
                v3 ^= 0x1234567;
            }
           
            //printf("%x\n", v3);
            v1 += (v3 + k[((v3 >> 11)| 0xffe00000) & 3]) ^ (v0 + ((v0<<4) ^ (v0 >> 5)));
            --v7;
        } while (v7);
#endif
        printf("%x\n", v3);
        v8 = v14;
        v3 = 0;
        ida_chars[v14] = v0 & 0xffffffff;
        ida_chars[v8 + 1] = v1 & 0xffffffff;
        i = v8 + 2;
    }
    for (int i = 0; i < 8; i++) {
         printf("%x\n", ida_chars[i]);
    }
    return 0;
}
//hgame{SEH_s0und5_50_1ntere5ting}