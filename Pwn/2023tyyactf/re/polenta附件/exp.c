
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
typedef unsigned char   uint8;
#define DELTA 0x61C88647           //固定的一个常量
#define MX (((z>>5^y<<2) + (y>>3^z<<4)) ^ ((sum^y) + (key[(p&3)^e] ^ z)))   //固定的运算
#define _BYTE  uint8
unsigned int get_sum(int n, unsigned int delat)
{
  unsigned int sum = 0;

  for(int i = 0; i < 52/n+6; i++){
    sum -= delat;
    if((sum >> 0x1f) == 0){
        //sum = 0x9E3668B8;
        sum ^= 0x9876543;
    }
    //printf("%x\n",sum);
  }

  return sum;
}


void btea(uint32_t *v, int n, uint32_t const key[4])   //v是要加密的两个元素的数组
{                                                      //n为数组的长度
    uint32_t y, z, sum;                                //无符号整型     
    unsigned p, rounds, e;                            
    if (n > 1)            /* Coding Part */   
    {
        rounds = 6 + 52/n;               //固定的得出轮数
        sum = 0;                        
        z = v[n-1];                     
        do
        {
            sum -= DELTA;                //每次进行叠加
            printf("%x\n",sum);
            e = (sum >> 2) & 3;          //固定运算
            for (p=0; p<n-1; p++)       
            {
                y = v[p+1];
                v[p] += MX;
                z = MX + v[p];     
            }
            y = v[0];
            z = v[n-1] += MX;
        }
        while (--rounds);
        
    }
    else if (n < -1)      /* Decoding Part */
    {
        n = -n;
        rounds = 6 + 52/n;
        sum = get_sum(n, DELTA); 
        //sum = rounds*DELTA;
        y = v[0];
        do
        {
            printf("%x\n",sum );
            e = (sum >> 2) & 3;
            for (p=n-1; p>0; p--)
            {
                z = v[p-1];
                y = v[p] -= MX;
            }
            z = v[n-1];
            y = v[0] -= MX;
            if((sum >> 0x1f) == 0){
                //sum = 0x9E3668B8;
                sum ^= 0x9876543;
                printf("%d ",rounds);
            }
            sum += DELTA;
            
        }
        while (--rounds);
    }
}

int main()
{
    //91b8439e f1ea37a9 846cc4dd dadf3d71 3e2e07e0 c142adc8 edac9fa7 4eae1d95 88abd0e7 6d466513
    uint32_t v[]= {0x9e43b891, 0xa937eaf1, 0xddc46c84, 0x713ddfda, 0xe0072e3e, 0xc8ad42c1, 0xa79faced, 0x951dae4e, 0xe7d0ab88,0x1365466d};
    //uint32_t v[]= {0x91b8439e, 0xf1ea37a9, 0x846cc4dd, 0xdadf3d71, 0x3e2e07e0, 0xc142adc8, 0xedac9fa7, 0x4eae1d95, 0x88abd0e7,0x6d466513};
    uint32_t const k[4]= {0x12345678, 0x90ABCDEF, 0xDEADBEEF, 0x87654321};
    int n = 10; 

    btea(v, -n, k);
    printf("解密后的数据：\n");

    for(int i = 0; i < 4*n; i++)
    {
        printf("%c", ((unsigned char *)&v)[i]);
    }
    return 0;
}