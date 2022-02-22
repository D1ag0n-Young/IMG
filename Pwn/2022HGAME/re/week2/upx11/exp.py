# -*- coding: UTF-8 -*-
from z3 import *
import time
cmp_data =[
	0x8D68, 0x9D49,0x2A12,0x0AB1A
	,0x0CBDC,0x0B92B,0x2E32,0x9F59
	,0x0DDCD,0x9D49,0x0A90A,0x0E70
	,0x0F5CF,0x5ED5,0x3C03,0x7C87
	,0x2672,0xAB1A,0x0A50,0x5AF5
	,0x0FF9F,0x9F59,0x0BD0B,0x58E5
	,0x3823,0x0BF1B,0x78A7,0x0AB1A
	,0x48C4,0x0A90A,0x2C22,0x9F59
	,0x5CC5,0x5ED5,0x78A7,0x2672
	,0x5695
]

a = '''
  for ( i = 0; i < (unsigned __int64)len_0(v16); ++i )
  {
    v12 = *((char *)v16 + i) << 8;
    for ( j = 0; j <= 7; ++j )
    {
      if ( (v12 & 0x8000) != 0 )
        v12 = (2 * v12) ^ 0x1021;
      else
        v12 *= 2;
    }
    v15[i] = (unsigned __int16)v12;
  }'''


def Z3solver(tmp):

		tmp = tmp<<8
		for j in range(8):
			if ((tmp)&0x8000 ) != 0:
				tmp = (tmp *2)^0x1021
			else:
				tmp *= 2
		tmp = tmp&0xffff
		# print(hex(tmp))
		return tmp
	
for i in range(37):

	for j in range(33,127):
		re = Z3solver(j)
		if re == cmp_data[i]:
			print(chr(j),end='')
			break
#noW_YOu~koNw-rea1_UPx~mAG|C_@Nd~crC16
	


