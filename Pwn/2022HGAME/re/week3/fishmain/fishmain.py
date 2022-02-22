# -*- coding: utf-8 -*-
from Crypto.Cipher import Blowfish
import codecs
class blowfish():
    def __init__(self):
        pass
 
    def Encrypt(self,code,key):
        key = key.encode("utf-8")
        l=len(code)
        if l % 8 != 0 :
            code = code + ' ' * (8 - (l %8))#Blowfish底层决定了字符串长度必须8的整数倍，所补位空格也可以根据自己需要补位其他字符
        code = code.encode('utf-8')
        cl = Blowfish.new(key, Blowfish.MODE_ECB)
        encode = cl.encrypt(code)
        hex_encode = codecs.encode(encode, 'hex_codec')#可以根据自己需要更改hex_codec
        return hex_encode
 
    def Decrypt(self, string,key):
        key=key.encode("utf-8")
        string=string.encode("utf-8")
        cl = Blowfish.new(key, Blowfish.MODE_ECB)
        ciphertext = codecs.decode(string, 'hex_codec')#可以根据自己需要更改hex_codec
        code = cl.decrypt(ciphertext)
        return "%s" % (code)
 
if __name__ == '__main__':
    encode = '8749C71106E48B51'
    code = '11111111111111111111111111111111'
    key = b'6AF74079'
    gw = blowfish()
    print "明文密码：%s，经过key：%s加密之后的加密密码是：%s"%(code,key,gw.Encrypt(code,key))
    encode=gw.Encrypt(code,key)
    print "加密密码：%s，经过key：%s解密之后的明文密码是：%s"%(encode,key,gw.Decrypt(encode,key))