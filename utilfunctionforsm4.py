import base64
import binascii


def str_hex2str(a):
    y = int(a, 16)  # 输入的16进制字符串先以16进制转成10进制整形
    # bytes_y = y.to_bytes(int(len(a)/2),"big")
    str_y = val = '{0}'.format(y)
    # print(type(val), val)
    return str_y


#   Base64转HexStr
def b64_To_HexStr(baseb4):
    b1n = base64.b64decode(baseb4)
    HxStr = b1n.hex()
    return HxStr


#   HexStr转Base64
def hex_to_base64(payload_hex2):
    bytes_out = bytes.fromhex(payload_hex2)
    str_out = base64.b64encode(bytes_out)
    # print("hex_to_base64:", str_out)
    return str_out


def asciiTo_hex(s):
    list_h = []
    for c in s:
        list_h.append(str(hex(ord(c))[2:]))
    return ''.join(list_h)


def str_to_hexStr(self, hex_str):
    """
    字符串转hex
    :param hex_str: 字符串
    :return: hex
    """
    hex_data = hex_str.encode('utf-8')
    str_bin = binascii.unhexlify(hex_data)
    return str_bin.decode('utf-8')


def str2byte(b):
    # bytes object

    # str object
    # str to bytes
    x = bytes(b, encoding="utf8")
    return x
