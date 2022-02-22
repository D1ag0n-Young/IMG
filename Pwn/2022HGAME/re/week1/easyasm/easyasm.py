from z3 import *
seg001 = [  0x91, 0x61, 0x01, 0xC1, 0x41, 0xA0, 0x60, 0x41, 0xD1, 0x21, 
  0x14, 0xC1, 0x41, 0xE2, 0x50, 0xE1, 0xE2, 0x54, 0x20, 0xC1, 
  0xE2, 0x60, 0x14, 0x30, 0xD1, 0x51, 0xC0, 0x17]
print(len(seg001))
def Z3():
    s = Solver()
    flag = [BitVec(('x%d' % i), 8) for i in range(0x1c)]
    
    for i in range(0x1c):
        flag[i]=(((((flag[i]<<4)&0xffff) + ((flag[i]>>4)&0xffff))&0xffff)^0x17)&0xff
       
    for i in range(0x1c):
        s.add(flag[i] == seg001[i])
  
    if s.check() == sat:
        model = s.model()
        print(model)
        # for i in range(0x1c):
        #   print(model[flag[i]])
        # str = [chr(model[flag[i]].as_long().real) for i in range(32)]
        # print("".join(str))
        exit()
    else:
        print("unsat")
# Z3()
flag = {'x9':99,
 'x8':108,
 'x14':116,
 'x15':111,
 'x27':0,
 'x18':115,
 'x22':48,
 'x0':104,
 'x3':109,
 'x7':101,
 'x13':95,
 'x23':114,
 'x11':109,
 'x20':95,
 'x1':103,
 'x10':48,
 'x16':95,
 'x25':100,
 'x21':119,
 'x26':125,
 'x6':119,
 'x2':97,
 'x19':109,
 'x12':101,
 'x24':108,
 'x17':52,
 'x4':101,
 'x5':123}
for i in range(0x1c-1):
  s = 'x%d'%i
  print(chr(flag.get(s)),end='')

 