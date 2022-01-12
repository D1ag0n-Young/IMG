array1 = [83 ,69,65]
array2 = [101,108,111,117,122,101,105,98,101,108,117,105,113,117,105,113]
array1 = array1[::-1]
array2 = array2[::-1]
arry = []
for i in range(256):
	arry.append(i)
for i in range(256):
	arry[i] += array1[i%3]
	arry[i] += array2[i%16]
	arry[i] = arry[i] % 256

for j in range(3):
	for i in range(256):
		arry[i] ^= arry[(i+1)%256]
	for k in range(256):
		arry[k]=(arry[k]+1)%256	


q = 0		
for p in range(256):
	q = arry[p]+q
	

q *= 20
q = q+5
q*=30
q-=5
q*=40
q-=5
q*=50
q+=6645

print (q)

