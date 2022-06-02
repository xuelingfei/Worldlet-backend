# -*- coding: utf-8 -*-
from Cryptodome.Cipher import AES
from binascii import b2a_hex, a2b_hex
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms


def pkcs7_padding(data):
    """
    PKCS7Padding 填充，假设数据长度需要填充 n(n>0) 个字节才对齐，那么填充 n 个字节，每个字节都是 n；
    如果数据本身就已经对齐了，则填充一块长度为块大小的数据，每个字节都是块大小。
    :param data: str
    :return: bytes
    """
    if not isinstance(data, bytes):
        data = data.encode('utf-8')
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data


def pkcs7_unpadding(padded_data):
    """
    PKCS7Padding 填充
    :param padded_data: bytes
    :return: bytes
    """
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    data = unpadder.update(padded_data)
    try:
        uppadded_data = data + unpadder.finalize()
    except ValueError:
        raise Exception('无效的信息!')
    else:
        return uppadded_data


def encrypt(value, key="1234123412ABCDEF", iv="ABCDEF1234123412"):
    """
    AES CBC加密
    :param value:
    :param key:
    :param iv:
    :return:
    """
    key = key.encode('utf-8')  # 密钥
    iv = iv.encode('utf-8')  # 偏移量
    mode = AES.MODE_CBC
    value = value.encode('utf-8')  # 对数据进行utf-8编码
    cryptor = AES.new(key, mode, iv)  # 创建一个新的AES实例
    ciphertext = cryptor.encrypt(pkcs7_padding(value))  # 加密字符串
    ciphertext_hex = b2a_hex(ciphertext)  # 字符串转十六进制数据
    ciphertext_hex_de = ciphertext_hex.decode()
    return ciphertext_hex_de.upper()


def decrypt(text, key="1234123412ABCDEF", iv="ABCDEF1234123412"):
    """
    AES CBC解密
    :param text:
    :param key:
    :param iv:
    :return:
    """
    #  偏移量'iv'
    key = key.encode('utf-8')  # 密钥
    iv = iv.encode('utf-8')  # 偏移量
    mode = AES.MODE_CBC
    cryptor = AES.new(key, mode, iv)
    plain_text = cryptor.decrypt(a2b_hex(text))
    # return plain_text.rstrip('\0')
    return bytes.decode(plain_text).rstrip("\x01"). \
        rstrip("\x02").rstrip("\x03").rstrip("\x04").rstrip("\x05"). \
        rstrip("\x06").rstrip("\x07").rstrip("\x08").rstrip("\x09"). \
        rstrip("\x0a").rstrip("\x0b").rstrip("\x0c").rstrip("\x0d"). \
        rstrip("\x0e").rstrip("\x0f").rstrip("\x10")
