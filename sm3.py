from gmssl import sm3

# 计算SM3哈希值
def sm3_hash(msg):
    msg=bytearray(msg)
    h = sm3.sm3_hash(msg)
    return h

msg = b'Hello xh!'
hash_value = sm3_hash(msg)
print(hash_value)
