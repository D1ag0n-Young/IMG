#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <string.h>
#include <unistd.h>

unsigned char result[32];

void print(char *str) {
   write(1,str,strlen(str));
}

// char hash[33] = "\x00\x00\x00";

int main(char* hash) {
   char prex[4] = {0};
   write(1,"prex:",5);
   read(0,prex,10);
   for (int a=0;a<0x80;a++) {
      prex[0] = a;
      for (int b=0;b<0x80;b++) {
         prex[1] = b;
         for (int c=0;c<0x80;c++) {
            prex[2] = c;
            for (int d=0;d<0x80;d++) {
               prex[3] = d;
               SHA256((const unsigned char*)prex,4,result);
               if (!memcmp(hash,result,32)) {
                  printf("ok\n");
                  write(1,prex+10,4);
                  exit(0);
               }
            }
         }
      }
   }

}
