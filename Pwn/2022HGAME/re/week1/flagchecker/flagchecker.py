import sys
import base64
from Crypto.Cipher import  ARC4

class rc4util():
    def __init__(self,key):
        if isinstance(key,str):
            self.__keyGen = key.encode()
        elif isinstance(key,bytes):
            self.__keyGen = key
    def __encrypt(self,data) ->bytes:
        rc4 = ARC4.new( self.__keyGen)
        res = rc4.encrypt(data)
        res = base64.b64encode(res)
        return res
    def __decrypt(self,data)->bytes:
        rc4 = ARC4.new(self.__keyGen)
        res = base64.b64decode(data)
        res = rc4.decrypt(res)
        return res
    def encrypt(self,src)->bytes:  
        res = self.__encrypt(src)    
        return res
    def decrypt(self,src)->bytes:    
        res = self.__decrypt(src)           
        return res


def Entry(src,key):
    rc4 = rc4util(key)
    bret = rc4.encrypt(src)

    if bret:
        print("加密成功:",bret)
    else:
        print("加密失败")


def Decry(src,key):
    rc4 = rc4util(key)
    bret = rc4.decrypt(src)
    if bret:
        print("解密成功:",bret)
    else:
        print("解密失败")

if __name__ == "__main__":
    key = b'carol'
    src = b"xxxsrcFile"  #这里是读取src文件数据,然后对其进行加密.加密的结果写入到dst文件中
    encstr = b"mg6CITV6GEaFDTYnObFmENOAVjKcQmGncF90WhqvCFyhhsyqq1s="
    Entry(src,key)
    Decry(encstr,key)