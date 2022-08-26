# -*- coding: utf-8 -*-
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from hmac import compare_digest
from hmac import new as hmac_new
from secrets import token_hex

from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import RSA
from Cryptodome.Util.Padding import pad, unpad


class CypherHash:
    @staticmethod
    def salt_sha(cypher):
        """
        sha256加盐散列，使用 secrets 生成的十六进制随机文本字符串作为随机盐

        Args:
            cypher (str): 密码或需要散列的数据
        Return:
            str: 散列值 + 盐值
        """
        random_salt = token_hex(16)
        ciphertext = sha256((random_salt + cypher).encode('utf-8')).hexdigest()
        return ciphertext + random_salt

    @staticmethod
    def hmac_sha(cypher):
        """
        hmac 加密散列，使用 sha256 算法，使用 secrets 生成的十六进制随机文本字符串作为随机密钥

        Args:
            cypher (str): 密码或需要散列的数据
        Return:
            str: 散列值 + 密钥
        """
        random_key = token_hex(16)
        ciphertext = hmac_new(random_key.encode('utf-8'), cypher.encode('utf-8'), 'sha256').hexdigest()
        return ciphertext + random_key

    @staticmethod
    def compare(value, target, method='hmac_sha'):
        """
        返回 value == target。value 和 target 必须为相同的类型：或者是 str (仅限 ASCII 字符)，或者是 bytes-like object。

        Args:
            value (str or bytes): 需要对比验证的值
            target (str or bytes): 用来对比的对象
            method (str): 生成 target 时所使用的方法
        Return:
            bool: 对比结果
        """
        if method == 'salt_sha':
            key = target[-32:]
            ciphertext = sha256((key + value).encode('utf-8')).hexdigest()
            result = ciphertext + key
        elif method == 'hmac_sha':
            key = target[-32:]
            ciphertext = hmac_new(key.encode('utf-8'), value.encode('utf-8'), 'sha256').hexdigest()
            result = ciphertext + key
        else:
            result = value
        return compare_digest(result, target)


secret_key = '5e999a220eefebb9'


class CypherAES:
    @staticmethod
    def encrypt(data, key=secret_key):
        """
        AES 加密，CBC 模式

        Args:
          data (str): 需要加密的数据
          key (str): 密钥
        Return:
          str: 加密的结果
        """
        padded_data = pad(data.encode('utf-8'), AES.block_size, 'pkcs7')
        cryptor = AES.new(key.encode('utf-8'), AES.MODE_CBC)
        encrypted_data = cryptor.iv + cryptor.encrypt(padded_data)
        ciphertext = b2a_hex(encrypted_data).decode('utf-8').upper()
        return ciphertext

    @staticmethod
    def decrypt(data, key=secret_key):
        """
        AES 解密，CBC 模式

        Args:
          data (str): 需要解密的数据
          key (str): 密钥
        Return:
          str: 解密的结果
        """
        data = a2b_hex(data.encode('utf-8'))
        cryptor = AES.new(key.encode('utf-8'), AES.MODE_CBC, data[:16])
        decrypted_data = cryptor.decrypt(data[16:])
        uppadded_data = unpad(decrypted_data, AES.block_size, 'pkcs7')
        plain_text = uppadded_data.decode('utf-8')
        return plain_text


class CypherRSA:
    @staticmethod
    def generate_key(bits=2048):
        """
        创建并存储 RSA 密钥对

        Args:
          bits (integer):
            Key length, or size (in bits) of the RSA modulus.
            It must be at least 1024, but **2048 is recommended.**
            The FIPS standard only defines 1024, 2048 and 3072.
        """
        key = RSA.generate(bits)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
