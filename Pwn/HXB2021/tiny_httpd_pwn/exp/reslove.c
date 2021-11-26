#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <stdint.h>
int main(){
    char path[512]={"/.../.../.../.../.../.../.../...//...//.../bin/bash"};
    int len = strlen(path);
    int i,j;
    for (i = 0, j = 0; j < len;) {
        if (path[j] == '.' && path[j + 1] == '.') { 
            j++;
        }
        path[i++] = path[j++];
    }
    path[i++] = '\0';
    printf("%s",path);
    //execl(path, NULL);
}
