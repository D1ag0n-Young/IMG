#include <stdio.h>
#include <stdlib.h>

int main() {
    srand(0x1BF52);
    int num = 0;
    int Floor_num = 0; // 假设 Floor_num 的值为 100
    for(int i =0;i<100;i++){
        int fbss = rand() % 114514 % (Floor_num + 1);
        printf("%d,", fbss);
        num += Floor_num;
        Floor_num++;
    }
    printf("%d",num);
    return 0;
}
