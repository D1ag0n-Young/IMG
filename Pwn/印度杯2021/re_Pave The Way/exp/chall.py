
import re

i = 277

w = ''

while True:
    with open(f'c{i}.java') as f:
        s = f.read()
    try:
        m = re.search(r'var0 = var0 .*', s)
        print('m: ',m)
        m1 = re.search(r'.*pave\(var0\)', s)
        #print('m1: ',m1)
        #print('m.group()',m.group())
        #print('m.group()[:-1]',m.group()[:-1].split()[-1])

        w += m.group()[:-1].split()[-1].replace('"','')

        i = int(m1.group().strip()[1:].split('.')[0])
        print(i)

    except:
        break

print(w)

# COMPFEST13{WhaY_j4r_ne3d_MaNiFeSt_file_oOf_bafc2b182e}

