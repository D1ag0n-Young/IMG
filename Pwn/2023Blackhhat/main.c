#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SIZE_SMALL 0x40
#define SIZE_BIG   0x80

char *g_buf;

int getint(const char *msg) {
  int val;
  printf("%s", msg);
  if (scanf("%d%*c", &val) != 1) exit(1);
  return val;
}

int main() {
  setvbuf(stdout, NULL, _IONBF, 0);

  while (1) {
    puts("1. new\n2. show\n3. delete");
    switch (getint("> ")) {
      case 1: { /* new */
        if (g_buf) {
          puts("[-] Buffer in use");
          break;
        }

        if (getint("Size [1=small / 2=big]: ") == 1) {
          g_buf = (char*)malloc(SIZE_SMALL);
        } else {
          g_buf = (char*)malloc(SIZE_BIG);
        }

        printf("Data: ");
        read(STDIN_FILENO, g_buf, SIZE_BIG);
        g_buf[strcspn(g_buf, "\n")] = '\0';
        break;
      }

      case 2: { /* show */
        if (!g_buf) {
          puts("[-] Empty buffer");
        } else {
          printf("Data: %s\n", g_buf);
        }
        break;
      }

      case 3: { /* delete */
        if (!g_buf) {
          puts("[-] Empty buffer");
        } else {
          free(g_buf);
          g_buf = NULL;
        }
        break;
      }

      default:
        puts("[+] Bye!");
        return 0;
    }
  }
}
