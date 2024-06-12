# 2024川大网安密码学最后实验
import base64
import random
import string
import secrets
import binascii
from gmssl import sm3
from sm2 import  SM2Util
import sm4
import utilfunctionforsm4

from sm4 import SM4_cbc

# 首先生成一个5m大小的随机文件当作明文
#
# 定义文件大小（5MB）
file_size = 5 * 1024 * 1024

# 生成随机英文字母序列并写入文件
with open("plaintext.txt", "w") as f:
    while file_size > 0:
        # 每次写入最多1MB的随机英文字母序列
        chunk_size = min(1024 * 1024, file_size)
        random_letters = ''.join(random.choices(string.ascii_letters, k=chunk_size))
        f.write(random_letters)
        file_size -= chunk_size
print("随机明文序列文件plaintext.txt生成完成")
# 现在随机生成公钥和私钥

print("随机生成公钥和私钥")
secret_int = None

e = SM2Util.GenKeyPair(secret_int)
print(f"甲：我的私钥：{e[0]}，\n我的公钥{e[1][2:]}")

with open("pk1.txt",'w')as f:
    f.write(e[1][2:])
with open("sk1.txt",'w')as f:
    f.write(e[0])
e = SM2Util.GenKeyPair(secret_int)
print(f"乙：我的私钥：{e[0]}，\n我的公钥:{e[1][2:]}")
with open("pk2.txt",'w')as f:
    f.write(e[1][2:])
with open("sk2.txt",'w')as f:
    f.write(e[0])
# 然后随机生成一个对称密钥128位k，并写入到key.txt中
# 生成128位（16字节）随机密钥
key = secrets.token_bytes(16)

# 将密钥转换为16进制格式
hex_key = binascii.hexlify(key)

# 将转换后的密钥写入文件
with open("key.txt", "w") as f:
    f.write(hex_key.decode())

print("对称密钥生成并转换为16进制，并保存到key.txt文件中")

# 然后生成一个vi用于CBC模式下的加密，并写入到iv.txt中
#
# 生成128位（16字节）随机iv
key = secrets.token_bytes(16)

# 将iv转换为16进制格式
hex_key = binascii.hexlify(key)

# 将转换后的vi写入文件
with open("iv.txt", "w") as f:
    f.write(hex_key.decode())

print("vi生成并转换为16进制，并保存到iv.txt文件中")

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

# 数字签名使用的是事先准备好的公钥和私钥，甲为pk1,sk1;乙为pk2,sk2

# 接下来实现整个流程

# 读取所需内容


with open("key.txt",'r') as f:
    key=f.read()
with open("iv.txt",'r') as f:
    iv=f.read()
with open("pk1.txt",'r') as f:
    pk1=f.read()
with open("pk2.txt",'r') as f:
    pk2=f.read()
with open("sk1.txt",'r') as f:
    sk1=f.read()
with open("sk2.txt",'r') as f:
    sk2=f.read()
with open("plaintext.txt",'r') as f:
    fiveMb=f.read()

甲=SM2Util(pk1,sk1)
乙=SM2Util(pk2,sk2)
testdata=fiveMb
# 对称加密
print("\n甲：利用sm4加密明文")
cypertext=SM4encrypt(key,iv,testdata)
with open("crypto_text.txt",'w')as f:
    f.write(cypertext)

# 哈希值
print("\n甲：利用sm3获取明文哈希值")
hash_text=sm3_hash(utilfunctionforsm4.str2byte(testdata))
print(hash_text)
#甲的签名
print("\n甲：我现在利用自己的私钥签名得到的哈希值")
sign1=甲.Sign(hash_text)
with open("sign.txt",'w')as f:
    f.write(sign1)
print(sign1)
# 甲利用乙的公钥加密key
print("\n甲：我现在利用乙的公钥加密对称密钥")
crypt_key=乙.Encrypt(key)
with open('crypt_key.txt',"w")as f:
    f.write(crypt_key)

#乙恢复对称加密密钥
print("\n乙：我现在利用自己的私钥恢复对称加密密钥")
reverse_key=乙.Decrypt(crypt_key)
print(reverse_key)
assert reverse_key==key

#乙利用对称加密密钥恢复明文
print("\n乙：我现在利用对称密钥解密")
decrypt_text=SM4decrypt(cypertext,reverse_key,iv)
print("恢复明文成功")

# 乙对甲的签名进行验证
print("\n乙：我现在对甲的签名进行验证，首先我将算出明文的哈希值，之后进行签名验证")
hash_text2=sm3_hash(utilfunctionforsm4.str2byte(decrypt_text))
assert hash_text2==hash_text
verify=甲.Verify(hash_text2,sign1)
print("签名验证结果："+str(verify))