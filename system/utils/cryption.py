# -*- coding: utf-8 -*-
from binascii import b2a_hex, a2b_hex
from hashlib import sha256
from hmac import compare_digest
from hmac import new as hmac_new
from secrets import token_hex

from Cryptodome.Cipher import AES, PKCS1_OAEP as PKCS1_CIPHER
from Cryptodome.Hash.SHA1 import SHA1Hash
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_PSS as PKCS1_SIGNATURE
from Cryptodome.Util.Padding import pad, unpad

from worldlet.settings import AES_KEY, RSA_KEY, RSA_PRIVATE_KEY_PATH, RSA_PUBLIC_KEY_PATH


class CypherHash:
    @staticmethod
    def salt_sha(data):
        """
        sha256加盐散列，使用 secrets 生成的十六进制随机文本字符串作为随机盐

        Args:
            data (str): 需要散列的数据
        Return:
            str: 散列值 + 盐值
        """
        random_salt = token_hex(16)
        cypher_text = sha256((random_salt + data).encode('utf-8')).hexdigest()
        return cypher_text + random_salt

    @staticmethod
    def hmac_sha(data):
        """
        hmac 加密散列，使用 sha256 算法，使用 secrets 生成的十六进制随机文本字符串作为随机密钥

        Args:
            data (str): 需要散列的数据
        Return:
            str: 散列值 + 密钥
        """
        random_key = token_hex(16)
        cypher_text = hmac_new(random_key.encode('utf-8'), data.encode('utf-8'), 'sha256').hexdigest()
        return cypher_text + random_key

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
            cypher_text = sha256((key + value).encode('utf-8')).hexdigest()
            result = cypher_text + key
        elif method == 'hmac_sha':
            key = target[-32:]
            cypher_text = hmac_new(key.encode('utf-8'), value.encode('utf-8'), 'sha256').hexdigest()
            result = cypher_text + key
        else:
            result = value
        return compare_digest(result, target)


class CypherAES:
    @staticmethod
    def encrypt(plain_text, key=AES_KEY):
        """
        AES 加密，CBC 模式

        Args:
          plain_text (str): 明文
          key (str): 密钥
        Return:
          str: 密文
        """
        padded_data = pad(plain_text.encode('utf-8'), AES.block_size, 'pkcs7')
        cryptor = AES.new(key.encode('utf-8'), AES.MODE_CBC)
        encrypted_data = cryptor.iv + cryptor.encrypt(padded_data)
        cypher_text = b2a_hex(encrypted_data).decode('utf-8').upper()
        return cypher_text

    @staticmethod
    def decrypt(cypher_text, key=AES_KEY):
        """
        AES 解密，CBC 模式

        Args:
          cypher_text (str): 密文
          key (str): 密钥
        Return:
          str: 明文
        """
        encrypted_data = a2b_hex(cypher_text)
        cryptor = AES.new(key.encode('utf-8'), AES.MODE_CBC, encrypted_data[:16])
        decrypted_data = cryptor.decrypt(encrypted_data[16:])
        uppadded_data = unpad(decrypted_data, AES.block_size, 'pkcs7')
        plain_text = uppadded_data.decode('utf-8')
        return plain_text


class CypherRSA:
    @staticmethod
    def generate_key(bits=2048, private_key_path=RSA_PRIVATE_KEY_PATH, public_key_path=RSA_PUBLIC_KEY_PATH):
        """
        创建并存储 RSA 密钥对

        Args:
          bits (integer):
            Key length, or size (in bits) of the RSA modulus.
            It must be at least 1024, but **2048 is recommended.**
            The FIPS standard only defines 1024, 2048 and 3072.
          private_key_path (str): 私钥存储路径
          public_key_path (str): 公钥存储路径
        """
        key = RSA.generate(bits)
        private_key = key.export_key(passphrase=RSA_KEY, pkcs=8, protection="scryptAndAES128-CBC")
        public_key = key.publickey().export_key()
        with open(private_key_path, mode='wb') as f:
            f.write(private_key)
        with open(public_key_path, mode='wb') as f:
            f.write(public_key)

    @staticmethod
    def import_private_key(path=RSA_PRIVATE_KEY_PATH):
        try:
            with open(path, mode='rb') as f:
                encrypted_key_data = f.read()
            private_key = RSA.import_key(encrypted_key_data, passphrase=RSA_KEY)
            return private_key
        except Exception as err:
            raise Exception('RSA 私钥获取失败！' + repr(err))

    @staticmethod
    def import_public_key(path=RSA_PUBLIC_KEY_PATH):
        try:
            with open(path, mode='rb') as f:
                key_data = f.read()
            public_key = RSA.import_key(key_data)
            return public_key
        except Exception as err:
            raise Exception('RSA 公钥获取失败！' + repr(err))

    @staticmethod
    def encrypt(plain_text):
        """
        RSA 加密，PKCS1_OAEP 模式

        Args:
          plain_text (str): 明文
        Return:
          str: 密文
        """
        public_key = CypherRSA.import_public_key()
        cryptor = PKCS1_CIPHER.new(public_key)
        encrypted_data = cryptor.encrypt(plain_text.encode('utf-8'))
        cypher_text = b2a_hex(encrypted_data).decode('utf-8').upper()
        return cypher_text

    @staticmethod
    def decrypt(cypher_text):
        """
        RSA 解密，PKCS1_OAEP 模式

        Args:
          cypher_text (str): 密文
        Return:
          str: 明文
        """
        encrypted_data = a2b_hex(cypher_text)
        private_key = CypherRSA.import_private_key()
        cryptor = PKCS1_CIPHER.new(private_key)
        decrypted_data = cryptor.decrypt(encrypted_data)
        plain_text = decrypted_data.decode('utf-8')
        return plain_text

    @staticmethod
    def sign(data):
        """
        RSA 签名，PKCS1_PSS模式，采用 sha1 散列算法

        Args:
            data (str): 需要签名的数据
        Return:
            str: 签名
        """
        private_key = CypherRSA.import_private_key()
        cryptor = PKCS1_SIGNATURE.new(private_key)
        signed_data = cryptor.sign(SHA1Hash(data.encode('utf-8')))
        signature = b2a_hex(signed_data).decode('utf-8').upper()
        return signature

    @staticmethod
    def verify(data, signature):
        """
        RSA 验签，PKCS1_PSS模式，采用 sha1 散列算法

        Args:
            data (str): 需验证签名的数据
            signature (str): 需验证的对应签名
        Return:
            bool: 验证结果
        """
        public_key = CypherRSA.import_public_key()
        cryptor = PKCS1_SIGNATURE.new(public_key)
        digest = SHA1Hash(data.encode('utf-8'))
        return cryptor.verify(digest, a2b_hex(signature))
