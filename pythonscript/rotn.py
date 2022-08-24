'''
Author: yrl
date : 2022/8/1
'''
import string
import argparse

parser = argparse.ArgumentParser(
    usage="""

python3 rotN.py [-dec] [-h] [-n] [-u] [-l] [-d] [-m] message

Three parameters are optional, the default is the original string
eg: python3 rotN.py -n13 -u -l -d -m message # this table is a-z A-Z 0-9
eg: python3 rotN.py -n13 -s asdfghjklqwertyuASDcv -m message # custom table
eg: python3 rotN.py -n13 -dec -s asdfghjklqwertyuASDcv -m message # custom table and decrypt mode
  """,
    description="This is rotN process."
)
parser.add_argument(
    '-dec', '--decrypt', help='enable decrypt mode', default=False, action='store_true')
parser.add_argument(
    '-n', '--N', help='ROTN,plz choice the number of 3-24.', default=13, type=int,
    choices=[3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24])
parser.add_argument(
    '-u', '--upper', help='Convert plain text with uppercase,default=False', default=False, action='store_true')
parser.add_argument(
    '-l', '--lower', help='Convert plain text with lowercase,default=False', default=False, action='store_true')
parser.add_argument(
    '-d', '--digits', help='Convert plain text with digitscase,default=False', default=False, action='store_true')
parser.add_argument(
    '-s', '--strings', help='Custom rot table')
parser.add_argument(
    '-m', '--message', help='ROTN message.', default="V nz gur qrsnhyg!")
args = parser.parse_args()
word = args.message

lowercase = string.ascii_lowercase  # abcdefghijklmnopqrstuvwxyz
uppercase = string.ascii_uppercase  # ABCDEFGHIJKLMNOPQRSTUVWXYZ
digitscase = string.digits  # 0123456789
customcase = args.strings  # custom table

# control case tables
lower = args.lower
upper = args.upper
digits = args.digits
N = args.N

print("rot%s: " % N, end='')
if not args.decrypt :
	for i in range(len(word)):
		flag = False
		for j in range(len(lowercase)):
			if lower and word[i] == lowercase[j]:  # search for lower
				print(lowercase[(j + N) % 26], end='')
				flag = True
				break
			elif upper and word[i] == uppercase[j]:  # search for upper
				print(uppercase[(j + N) % 26], end='')
				flag = True
				break
		if not flag:
			flag1 = False  # None of the characters match
			for j in range(len(digitscase)):
				if digits and word[i] == digitscase[j]:  # search for digits
					print(digitscase[(j + N) % 10], end='')
					flag1 = True
					break
			if customcase:
				for j in range(len(customcase)):
					if word[i] == customcase[j]:  # search for customcase
						print(customcase[(j + N) % (len(customcase))], end='')
						flag1 = True
						break
			if not flag1:
				print(word[i], end='')
	print()
else:
	for i in range(len(word)):
		flag = False
		for j in range(len(lowercase)):
			if lower and word[i] == lowercase[j]:  # search for lower
				print(lowercase[(j - N) % 26], end='')
				flag = True
				break
			elif upper and word[i] == uppercase[j]:  # search for upper
				print(uppercase[(j - N) % 26], end='')
				flag = True
				break
		if not flag:
			flag1 = False  # None of the characters match
			for j in range(len(digitscase)):
				if digits and word[i] == digitscase[j]:  # search for digits
					print(digitscase[(j - N) % 10], end='')
					flag1 = True
					break
			if customcase:
				for j in range(len(customcase)):
					if word[i] == customcase[j]:  # search for customcase
						print(customcase[(j - N) % (len(customcase))], end='')
						flag1 = True
						break
			if not flag1:
				print(word[i], end='')
	print()
