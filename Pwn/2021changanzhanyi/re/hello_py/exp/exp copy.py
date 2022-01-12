Happy = [
    44,
    100,
    3,
    50,
    106,
    90,
    5,
    102,
    10,
    112]
num = 0

Happy[num] ^= Happy[num+1]
num += 1
Happy[num] ^= num
num += 1
Happy[num] ^= Happy[num+1]
num += 1
Happy[num] ^= num
num += 1
Happy[num] ^= Happy[num+1]
num += 1
Happy[num] ^= num
num += 1
Happy[num] ^= Happy[num+1]
num += 1
Happy[num] ^= num
num += 1
Happy[num] ^= Happy[num+1]
num += 1
Happy[num] ^= num
for i in Happy:
    print(chr(i),end='')