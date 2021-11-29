with open('../f/ASCII-faded 4157.txt','r',encoding='utf-8') as f:
	#content = f.read()
	flag = True
	i = 0
	while(flag):		
		f.seek(i)
		content = f.read(40)
		# print (content)
		if content == 'UzNDcmU3X0szeSUyMCUzRCUyMEFsNE5fd0FsSzNS':
			flag = False
			print ('offest:',i)
		i+=1
import urllib.parse
import base64
dec = base64.b64decode('UzNDcmU3X0szeSUyMCUzRCUyMEFsNE5fd0FsSzNS')
print(urllib.parse.unquote(str(dec,'utf-8')))
