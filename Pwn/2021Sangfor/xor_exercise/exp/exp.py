def multiply(multiplier_a, multiplier_b):
	    tmp = [0] * 64
	    res = 0
	    for i in range(64):
		tmp[i] = (multiplier_a << i) * ((multiplier_b >> i) & 1)
		res ^= tmp[i]
	    return res
def find_highest_bit(value):
    	i = 0
	while value != 0:
		i += 1
		value >>= 1
	return i
def divide(numerator, denominator):
    quotient = 0
    tmp = numerator
    bit_count = find_highest_bit(tmp) - find_highest_bit(denominator)
    while bit_count >= 0:
        quotient |= (1<< bit_count)
        tmp ^= (denominator << bit_count)
        bit_count = find_highest_bit(tmp) - find_highest_bit(denominator)
        remainder = tmp
        return quotient, remainder
def reverse(x, bits):
    bin_x = bin(x)[2:].rjust(bits, '0')
    re_bin_x = bin_x[::-1]
    return int(re_bin_x, 2)
cipher = [0x32e9a65483cc9671, 0xec92a986a4af329c, 0x96c8259bc2ac4673,
0x74bf5dca4423530f, 0x59d78ef8fdcbfab1, 0xa65257e5b13942b1]
res = b""
for a in cipher:
    d = 0xb1234b7679fc4b3d
    rr = reverse(a, 64)
    rd = reverse((1<< 64) + d, 65)
    q, r = divide(rr << 64, rd)
    r = reverse(r, 64)
    for i in range(8):
        res += bytes([r & 0xff])
        r >>= 8
    print(res)
print(res.decode())
