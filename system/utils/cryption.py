# -*- coding: utf-8 -*-
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from binascii import b2a_hex, a2b_hex

sk = '1234567890123456'


class CBC:

    @staticmethod
    def encrypt(data, key=sk):
        """
        AES CBC 加密

        Args:
          data (str): 需要加密的数据
          key (str): 密钥

        Return:
          str: 加密的结果
        """
        key = key.encode('utf-8')
        data = data.encode('utf-8')
        padded_data = pad(data, AES.block_size, 'pkcs7')
        cryptor = AES.new(key, AES.MODE_CBC)
        encrypted_data = cryptor.iv + cryptor.encrypt(padded_data)
        cipher_text = b2a_hex(encrypted_data).decode('utf-8').upper()
        return cipher_text

    @staticmethod
    def decrypt(data, key=sk):
        """
        AES CBC 解密

        Args:
          data (str): 需要解密的数据
          key (str): 密钥

        Return:
          str: 解密的结果
        """
        key = key.encode('utf-8')
        data = a2b_hex(data.encode('utf-8'))
        cryptor = AES.new(key, AES.MODE_CBC, data[:16])
        decrypted_data = cryptor.decrypt(data[16:])
        uppadded_data = unpad(decrypted_data, AES.block_size, 'pkcs7')
        plain_text = bytes.decode(uppadded_data, 'utf-8')
        return plain_text
