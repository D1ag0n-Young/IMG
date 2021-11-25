import base64
s = ''
with open('./out.back','rb') as f:
	list1 = f.read()
for i in list1:
	print hex(ord(i)),

print 
d=0
for j in list1:	
	d+=0xa0
	d=d & 0xff
	for i in range(128):
		if ((d-i)*5+2)&0xff == ord(j):
			s+=chr(i)
			d=((d-i)*5+2)&0xff
			break
			
print base64.b64decode(s) 
