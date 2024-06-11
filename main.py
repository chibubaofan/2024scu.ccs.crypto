#initailze用于初始化，包括5mb文件以及密钥等
# test使用testdata进行测试,可以运行test更好的了解程序流程
# main则完成命令行输入要求，使用5mb文件进行
import base64

import sm3
from sm2 import SM2Util
import argparse
import sm4
import utilfunctionforsm4

# 创建ArgumentParser对象
parser = argparse.ArgumentParser(description="main")
# 实现使用SM4加密的函数
def SM4encrypt(key,iv_str,str_data):
    # 输入皆为str类型，返回为str
    SM4=sm4.SM4_cbc()
    cipher = SM4.encrypt_cbc(key, iv_str, str_data)
    cipher_hex = cipher.decode()
    return cipher_hex

# 实现使用SM4解密的函数
def SM4decrypt(cipher_hex,key,iv_str):
    # 输入为str，返回为str
    SM4 = sm4.SM4_cbc()
    val = utilfunctionforsm4.hex_to_base64(cipher_hex)
    decode_cbc = SM4.decrypt_cbc(key, iv_str, base64.b64decode(val))
    return decode_cbc.decode()

#实现SM3哈希函数
def sm3_hash(msg):
    # 输入为字节串，返回为16进制字符串
    msg=bytearray(msg)
    h = sm3.sm3_hash(msg)
    return h
# 添加命令行参数
parser.add_argument("-p", default='plaintext.txt',type=str, help="明文文件")
parser.add_argument("-k", default='key.txt',type=str, help="密钥文件")
parser.add_argument("-c", default='crypto_text.txt',type=str, help="密文文件")
parser.add_argument("-ck", default='crypt_key.txt',type=str, help="密钥密文文件")
parser.add_argument("-s", default='sign.txt',type=str, help="签名文件")
parser.add_argument("-pk2", default='pk2.txt',type=str, help="乙方公钥")
# 解析命令行参数
args = parser.parse_args()
plaintext= args.p
key=args.k
ciphertext_path=args.c
cipher_key=args.ck
sign_path=args.s
pk2=args.pk2
# 读取所需参数
with open(cipher_key,'r')as f:
    cipher_key=f.read()
with open(key,'r') as f:
    key=f.read()
with open("iv.txt",'r') as f:
    iv=f.read()
with open("pk1.txt",'r') as f:
    pk1=f.read()
with open(pk2,'r') as f:
    pk2=f.read()
with open("sk1.txt",'r') as f:
    sk1=f.read()
with open("sk2.txt",'r') as f:
    sk2=f.read()
with open(plaintext,'r') as f:
    fiveMb=f.read()
乙 = SM2Util(pk2, sk2)
甲 = SM2Util(pk1, sk1)

# 功能a完成对密钥文件的解密，输出密钥并将密钥本地保存为恢复密钥文件；

reversed_key=乙.Decrypt(cipher_key)
print("乙：现在我将解密密钥密文并将解密后的密钥写入decrypt_key.txt")
if reversed_key==key:
    print("恢复正确")
    print("key:"+reversed_key)
    with open("decrypt_key.txt",'w') as f:
        f.write(reversed_key)
else:print("回复失败")

# 功能b完成对数据的解密，输出恢复的明文文件，将恢复的文件保存为恢复明文文件；
print("\n乙：现在我将解密数据并将解密后的数据写入decrypt_text.txt")
with open(ciphertext_path,'r')as f:
    ciphertext=f.read()
with open("decrypt_key.txt",'r')as f:
    reversed_key=f.read()
decrypt_text=SM4decrypt(ciphertext,reversed_key,iv)
print("解密成功")
with open("decrypt_text.txt","w")as f:
    f.write(decrypt_text)

# 功能c完成对甲方数字签名正确与否的验证，输出结果为true或false
print("\n乙：首先我会得到明文的哈希值，再利用哈希值和甲的公钥进行签名验证")
with open("decrypt_text.txt",'r')as f:
    decrypt_text=f.read()
print("获取明文的哈希值：")
hash_m=sm3_hash(utilfunctionforsm4.str2byte(decrypt_text))
print(hash_m)
with open(sign_path,'r')as f:
    sign=f.read()
print("验证数字签名：")
print(甲.Verify(hash_m,sign))

#功能d以命令行形式指定明文文件和恢复明文文件，如果两文件一致，则输出success，否则输出failure.
print("\n现在验证解密出来的内容是否与原内容相等")
with open("decrypt_text.txt",'r')as f:
    decrypt_text=f.read()
with open(plaintext,'r')as f:
    fiveMb=f.read()
if decrypt_text==fiveMb:
    print("Success!")
else:
    print("False!")
