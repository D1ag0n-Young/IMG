enc = [
  0x65, 0x55, 0x24, 0x36, 0x9D, 0x71, 0xB8, 0xC8, 0x65, 0xFB, 
  0x87, 0x7F, 0x9A, 0x9C, 0xB1, 0xDF, 0x65, 0x8F, 0x9D, 0x39, 
  0x8F, 0x11, 0xF6, 0x8E, 0x65, 0x42, 0xDA, 0xB4, 0x8C, 0x39, 
  0xFB, 0x99, 0x65, 0x48, 0x6A, 0xCA, 0x63, 0xE7, 0xA4, 0x79, 
  0xFF, 0xFF, 0xFF, 0xFF 
]

table = [
  0x65, 0x08, 0xF7, 0x12, 0xBC, 0xC3, 0xCF, 0xB8, 0x83, 0x7B, 
  0x02, 0xD5, 0x34, 0xBD, 0x9F, 0x33, 0x77, 0x76, 0xD4, 0xD7, 
  0xEB, 0x90, 0x89, 0x5E, 0x54, 0x01, 0x7D, 0xF4, 0x11, 0xFF, 
  0x99, 0x49, 0xAD, 0x57, 0x46, 0x67, 0x2A, 0x9D, 0x7F, 0xD2, 
  0xE1, 0x21, 0x8B, 0x1D, 0x5A, 0x91, 0x38, 0x94, 0xF9, 0x0C, 
  0x00, 0xCA, 0xE8, 0xCB, 0x5F, 0x19, 0xF6, 0xF0, 0x3C, 0xDE, 
  0xDA, 0xEA, 0x9C, 0x14, 0x75, 0xA4, 0x0D, 0x25, 0x58, 0xFC, 
  0x44, 0x86, 0x05, 0x6B, 0x43, 0x9A, 0x6D, 0xD1, 0x63, 0x98, 
  0x68, 0x2D, 0x52, 0x3D, 0xDD, 0x88, 0xD6, 0xD0, 0xA2, 0xED, 
  0xA5, 0x3B, 0x45, 0x3E, 0xF2, 0x22, 0x06, 0xF3, 0x1A, 0xA8, 
  0x09, 0xDC, 0x7C, 0x4B, 0x5C, 0x1E, 0xA1, 0xB0, 0x71, 0x04, 
  0xE2, 0x9B, 0xB7, 0x10, 0x4E, 0x16, 0x23, 0x82, 0x56, 0xD8, 
  0x61, 0xB4, 0x24, 0x7E, 0x87, 0xF8, 0x0A, 0x13, 0xE3, 0xE4, 
  0xE6, 0x1C, 0x35, 0x2C, 0xB1, 0xEC, 0x93, 0x66, 0x03, 0xA9, 
  0x95, 0xBB, 0xD3, 0x51, 0x39, 0xE7, 0xC9, 0xCE, 0x29, 0x72, 
  0x47, 0x6C, 0x70, 0x15, 0xDF, 0xD9, 0x17, 0x74, 0x3F, 0x62, 
  0xCD, 0x41, 0x07, 0x73, 0x53, 0x85, 0x31, 0x8A, 0x30, 0xAA, 
  0xAC, 0x2E, 0xA3, 0x50, 0x7A, 0xB5, 0x8E, 0x69, 0x1F, 0x6A, 
  0x97, 0x55, 0x3A, 0xB2, 0x59, 0xAB, 0xE0, 0x28, 0xC0, 0xB3, 
  0xBE, 0xCC, 0xC6, 0x2B, 0x5B, 0x92, 0xEE, 0x60, 0x20, 0x84, 
  0x4D, 0x0F, 0x26, 0x4A, 0x48, 0x0B, 0x36, 0x80, 0x5D, 0x6F, 
  0x4C, 0xB9, 0x81, 0x96, 0x32, 0xFD, 0x40, 0x8D, 0x27, 0xC1, 
  0x78, 0x4F, 0x79, 0xC8, 0x0E, 0x8C, 0xE5, 0x9E, 0xAE, 0xBF, 
  0xEF, 0x42, 0xC5, 0xAF, 0xA0, 0xC2, 0xFA, 0xC7, 0xB6, 0xDB, 
  0x18, 0xC4, 0xA6, 0xFE, 0xE9, 0xF5, 0x6E, 0x64, 0x2F, 0xF1, 
  0x1B, 0xFB, 0xBA, 0xA7, 0x37, 0x8F
]
tmp = []
for i in range(len(enc)):
	for j in range(len(table)):
		if table[j] == enc[i]:
			tmp.append(j)
print (tmp)

import z3
input = [z3.BitVec("p%d" % i,8) for i in range(40)]
v6 = [0]*8
v6[0] = 128;
v6[1] = 64;
v6[2] = 32;
v6[3] = 16;
v6[4] = 8;
v6[5] = 4;
v6[6] = 2;
v6[7] = 1;
s = z3.Solver()
for i in range(0,0x28,8):
    for  j in range(8):
        v5 = ((v6[j] & input[i + 3]) << (8 - (3 - j) %  8)) | ((v6[j] & input[i + 3]) >> ((3 - j) %  8)) | ((v6[j] & input[i + 2]) << (8 - (2 - j) %  8)) | ((v6[j] &  input[i + 2]) >> ((2 - j) %  8)) | ((v6[j] & input[i + 1]) << (8 - (1 - j) %  8)) | ((v6[j] &  input[i + 1]) >> ((1 - j) %  8)) | ((v6[j] & input[i]) << (8 - -j %  8)) | ((v6[j] &  input[i]) >> (-j %  8))
        v = ((v6[j] & input[i + 7]) << (8 - (7 - j) %  8)) | ((v6[j] & input[i + 7]) >> ((7 - j) %  8)) | ((v6[j] & input[i + 6]) << (8 - (6 - j) %  8)) | ((v6[j] &  input[i + 6]) >> ((6 - j) %  8)) | ((v6[j] & input[i + 5]) << (8 - (5 - j) %  8)) | ((v6[j] &  input[i + 5]) >> ((5 - j) %  8)) | ((v6[j] & input[i + 4]) << (8 - (4 - j) %  8)) | ((v6[j] &  input[i + 4]) >> ((4 - j) %  8))       
        s.add(v5 | v == tmp[i+j])
sat = s.check()
m = s.model()
flag = []
for i in range(len(m)):
	#print (input[i])
	flag.append(m[input[i]].as_long())
print (bytes(flag).decode())
'''
[0, 181, 122, 206, 37, 108, 7, 223, 0, 251, 124, 38, 75, 62, 134, 154, 0, 255, 37, 144, 255, 28, 56, 176, 0, 231, 60, 121, 225, 144, 251, 30, 0, 204, 179, 51, 78, 145, 65, 222, 29, 29, 29, 29]
Q5la5_3KChtem6_HYHk_NlHhNZz73aCZeK05II96

'''
