#include <stdio.h>
#include <stdlib.h>
#include <time.h>
 
int main()
{
   int i, n;
   time_t t;
   
   n = 5;
   
   /* 初始化随机数发生器 */
   srand(0x61616161);
 
   /* 输出 0 到 50 之间的 5 个随机数 */
   for( i = 0 ; i < 100 ; i++ ) {
      printf("%d,", rand() % 3);
   }
   
  return(0);
}
