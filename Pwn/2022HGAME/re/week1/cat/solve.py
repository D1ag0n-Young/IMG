# -*- coding: utf-8 -*-
from scipy import linalg
import numpy as np
import math
from z3 import *
import time
cmp_data =[0x25D15D4,0x24C73B4,0x243CF71,0x230134C,
    0x2132CFE,0x1BE2FCA,0x142CA26,0x0D61955,
    0x9427A8,0x9B8674,0x90C832,0x8812C7,
    0x80BA58,0x7981E1,0x72AB68,0x74CB4B,
    0x723F3F,0x7CC258,0x89CD5C,0x88E2A2,
    0x8E8906,0x8B88A0,0x8EEC8D,0x8F3573,
    0x8B746F,0x912C82,0x8D7CF2,0x832099,
    0x7F45A5,0x685AFF,0x50A4D2,0x526FE2,
    0x58923B,0x529EC1,0x516D1A,0x5B7453,
    0x7028E6,0x89C6FA,0x0A5D6AE,0x0D37A14,
    0x0B8CFAA,0x0B0BB4B,0x0AE69A4,0x0A1154B,
    0x9DCBE7,0x0A1DC20,0x0AA07E3,0x0B25CB1,
    0x0B2FD98,0x0B12F29,0x0E428A0,0x11B2184,
    0x1615722,0x1A502F3,0x1C0AA9D,0x1D4169F,
    0x1EF8B76,0x233E5BB,0x275A6F0,0x2A9CA35,
    0x2A8904C,0x2A194EF,0x2926F39,0x28E92C3
]
    
# print (len(cmp_data))
def hexstr2hex(hexstr):
    hexstr = hexstr[2:]
    return int(hexstr,16)

# export_results.txt
def openfile(name):
    with open(name,'r') as f:
        data = f.read()
    data = data.replace('\r','').replace('\n','').replace(' ','').split(',')
    # print(data)
    for i in range(len(data)):
        data[i] = hexstr2hex(data[i])
    tmp = []
    for i in range(0,len(data),4):
        tmp.append(data[i])
    return tmp
data1 = openfile('export_results.txt')
data2 = openfile('export_results1.txt')
print (len(data1),len(data2))

def makeresult(data):

    v9 = [0]*64
    for i in range(64):
        v3 = []
        for j in range(64):
             v3.append(data[((j<<6))+i]) 
        v9[i] = v3
        # print(v3)
    return v9
# print list(openfile('export_results.txt'))


def solvere():
    
    x_temp1 =  makeresult(data1)
    x_temp2 =  makeresult(data2)
    x_temp2=np.array(x_temp2)#转换为矩阵形式
    x_temp1=np.array(x_temp1)#转换为矩阵形式
    # print(type(x_temp1))
    #X_temp代表系数矩阵
    # C=[54,44,55]#C为常数列
    C = np.array(cmp_data)  # b代表常数列
    # round 1 
    X = linalg.solve(x_temp2,C)
    # round 2
    X = linalg.solve(x_temp1,X)
    for i in X:
        print(chr(int(round(i))),end='')

    
solvere()

# hgame{100011100000110000100000000110001010110000100010011001111}