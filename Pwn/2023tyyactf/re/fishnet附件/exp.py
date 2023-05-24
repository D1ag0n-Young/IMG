def sub_8049D85(a1,a2,a3):
    v7=0
    v8 =[0]*256
    for i in range(256):
        a1[i] = i
        v8[i] = a2[i % a3]
    for j in range(256):
        v7= (a1[j] + v7 + v8[j]) % 256
        v4=a1[j]
        a1[j] = a1[v7]^v4
        a1[v7] ^= v4
    return a1
def sub_8049F64(a1, a2,a3,a4):
    v9 = [0]*256
    v9 = sub_8049D85(v9,a3,a4)
    v6=0
    v7=0
    for i in range(a2):
        v6 = (v6+ 1)% 256
        v7=(v7 + v9[v6]) % 256
        v5 = v9[v6]
        v9[v6] = v9[v7]
        v9[v7] = v5
        a1[i] = (a1[i] - v9[(v9[v6] + v9[v7]) % 256]) % 256
    return a1
data = bytearray.fromhex( '399cd04e75f7e592353ac9f4d8381db434af95fd0c3b6f21fe2d3c0973e425d5d17d23f837ca')
key = bytearray(b'fishnet')
dec = sub_8049F64(data, len(data),key,7)
print(dec)