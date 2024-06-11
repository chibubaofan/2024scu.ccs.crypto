# -*-coding: utf-8-*-
import base64

from gmssl.sm4 import CryptSM4, SM4_ENCRYPT, SM4_DECRYPT
import  utilfunctionforsm4
import binascii

class SM4_cbc:

    def __init__(self):
        self.crypt_sm4 = CryptSM4()

    def str_to_strBin(self, hex_str):
        hex_data = hex_str.encode('utf-8')
        str_bin = binascii.unhexlify(hex_data)
        return str_bin.decode('utf-8')

    def encrypt_cbc(self, cbc_key, iv, value):
        crypt_cbc = self.crypt_sm4
        crypt_cbc.set_key(binascii.a2b_hex(cbc_key), SM4_ENCRYPT)
        Enc_value = crypt_cbc.crypt_cbc(binascii.a2b_hex(iv), value.encode())
        return binascii.b2a_hex(Enc_value)

    def decrypt_cbc(self, cbc_key, iv, value):
        crypt_cbc = self.crypt_sm4
        crypt_cbc.set_key(binascii.a2b_hex(cbc_key), SM4_DECRYPT)
        Dec_value = crypt_cbc.crypt_cbc(binascii.a2b_hex(iv), value)
        return Dec_value


if __name__ == '__main__':
    key = "b00b1e51ba8b9bfcd584ab5b73ab7660"
    str_data = "abc哎safsadfafdsafasdfdsafasdfasfsfasdfsafdsafsdaf"
    iv_str = "e5709dcac5e3016de93aaf7b364693c3"
    SM4 = SM4_cbc()
    print("待加密内容：", str_data)
    cipher = SM4.encrypt_cbc(key, iv_str, str_data)
    cipher_hex = cipher.decode()
    print("sm4_cbc加密后的结果：", cipher_hex, type(cipher_hex))
    val = utilfunctionforsm4.hex_to_base64(cipher_hex)
    decode_cbc = SM4.decrypt_cbc(key, iv_str, base64.b64decode(val))
    print("sm4_cbc解密结果是：", decode_cbc.decode(), "\n")





