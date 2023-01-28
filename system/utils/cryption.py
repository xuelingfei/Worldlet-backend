# -*- coding: utf-8 -*-
import hmac
import json
import secrets
from base64 import b64encode, b64decode
from binascii import b2a_hex, a2b_hex
from hashlib import sha256

from Cryptodome.Cipher import AES, PKCS1_OAEP as PKCS1_CIPHER
from Cryptodome.Hash.SHA1 import SHA1Hash
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_PSS as PKCS1_SIGNATURE
from Cryptodome.Util.Padding import pad, unpad

from worldlet.settings import AES_KEY, RSA_KEY, RSA_PRIVATE_KEY_PATH, RSA_PUBLIC_KEY_PATH


class CryptHash:
    """散列。sha256 加盐散列和 hmac 散列，推荐使用 hmac 散列。"""

    @staticmethod
    def sha_salt(data, nbytes=16):
        """
        SHA256 加盐散列，使用 secrets 生成的十六进制随机文本字符串作为随机盐。

        Args:
            data (str): 需要散列的数据
            nbytes (int): 随机盐所包含随机字节的个数
        Return:
            str: 散列值 + 盐值
        """
        try:
            random_salt = secrets.token_hex(nbytes)
            cypher_text = sha256((random_salt + data).encode('utf-8')).hexdigest()
            return cypher_text + random_salt
        except Exception as err:
            print('CryptHash sha256 加盐散列出错')
            raise Exception(err)

    @staticmethod
    def hmac_sha(data, nbytes=16):
        """
        hmac 散列，使用 SHA256 算法，使用 secrets 生成的十六进制随机文本字符串作为随机密钥。

        Args:
            data (str): 需要散列的数据
            nbytes (int): 随机密钥所包含随机字节的个数
        Return:
            str: 散列值 + 密钥
        """
        try:
            random_key = secrets.token_hex(nbytes)
            cypher_text = hmac.new(random_key.encode('utf-8'), data.encode('utf-8'), 'sha256').hexdigest()
            return cypher_text + random_key
        except Exception as err:
            print('CryptHash hmac 散列出错')
            raise Exception(err)

    @staticmethod
    def compare(value, target, method='hmac_sha', nbytes=16):
        """
        值比对。返回 value == target。value 和 target 必须为相同的类型：或者是 str (仅限 ASCII 字符)，或者是 bytes-like object。

        Args:
            value (str or bytes): 需要对比验证的值
            target (str or bytes): 用来对比的对象
            method (str): 生成 target 时所使用的方法，默认 hmac_sha
            nbytes (int): 所使用随机盐或密钥所包含随机字节的个数，每个字节转换为两个十六进制数字
        Return:
            bool: 对比结果
        """
        try:
            if method == 'sha_salt':
                key = target[-nbytes * 2:]
                cypher_text = sha256((key + value).encode('utf-8')).hexdigest()
                result = cypher_text + key
            elif method == 'hmac_sha':
                key = target[-nbytes * 2:]
                cypher_text = hmac.new(key.encode('utf-8'), value.encode('utf-8'), 'sha256').hexdigest()
                result = cypher_text + key
            else:
                result = value
            return hmac.compare_digest(result, target)
        except Exception as err:
            print('CryptHash 值比对出错')
            raise Exception(err)


class CryptSymmetry:
    """对称加密。AES 算法，CBC 模式。"""

    @staticmethod
    def encrypt(plain_text, key=AES_KEY):
        """
        AES-CBC 加密。

        Args:
          plain_text (str): 明文
          key (str): 密钥
        Return:
          str: 加密结果
        """
        try:
            padded_data = pad(plain_text.encode('utf-8'), AES.block_size, 'pkcs7')
            cryptor = AES.new(key.encode('utf-8'), AES.MODE_CBC)
            encrypted_data = cryptor.iv + cryptor.encrypt(padded_data)
            crypt_result = b2a_hex(encrypted_data).decode('utf-8').upper()
            return crypt_result
        except Exception as err:
            print('CryptSymmetry AES-CBC 加密出错')
            raise Exception(err)

    @staticmethod
    def decrypt(crypt_result, key=AES_KEY):
        """
        AES-CBC 解密。

        Args:
          crypt_result (str): 加密数据
          key (str): 密钥
        Return:
          str: 明文
        """
        try:
            encrypted_data = a2b_hex(crypt_result)
            cryptor = AES.new(key.encode('utf-8'), AES.MODE_CBC, encrypted_data[:16])
            decrypted_data = cryptor.decrypt(encrypted_data[16:])
            uppadded_data = unpad(decrypted_data, AES.block_size, 'pkcs7')
            plain_text = uppadded_data.decode('utf-8')
            return plain_text
        except Exception as err:
            print('CryptSymmetry AES-CBC 解密出错')
            raise Exception(err)


class CryptAsymmetry:
    """非对称加密。RSA 算法。"""

    @staticmethod
    def generate_key(bits=2048, private_key_path=RSA_PRIVATE_KEY_PATH, public_key_path=RSA_PUBLIC_KEY_PATH):
        """
        创建并存储 RSA 密钥对。

        Args:
          bits (integer):
            Key length, or size (in bits) of the RSA modulus.
            It must be at least 1024, but **2048 is recommended.**
            The FIPS standard only defines 1024, 2048 and 3072.
          private_key_path (str): 私钥存储路径
          public_key_path (str): 公钥存储路径
        """
        try:
            key = RSA.generate(bits)
            private_key = key.export_key(passphrase=RSA_KEY, pkcs=8, protection="scryptAndAES128-CBC")
            public_key = key.publickey().export_key()
            with open(private_key_path, mode='wb') as f:
                f.write(private_key)
            with open(public_key_path, mode='wb') as f:
                f.write(public_key)
        except Exception as err:
            print('CryptAsymmetry 创建并存储 RSA 密钥对出错')
            raise Exception(err)

    @staticmethod
    def import_private_key(path=RSA_PRIVATE_KEY_PATH):
        """获取 RSA 私钥（scryptAndAES128-CBC 加密）。"""
        try:
            with open(path, mode='rb') as f:
                encrypted_key_data = f.read()
            private_key = RSA.import_key(encrypted_key_data, passphrase=RSA_KEY)
            return private_key
        except Exception as err:
            print('CryptAsymmetry 获取 RSA 私钥出错')
            raise Exception(err)

    @staticmethod
    def import_public_key(path=RSA_PUBLIC_KEY_PATH):
        """获取 RSA 公钥。"""
        try:
            with open(path, mode='rb') as f:
                key_data = f.read()
            public_key = RSA.import_key(key_data)
            return public_key
        except Exception as err:
            print('CryptAsymmetry 获取 RSA 公钥出错')
            raise Exception(err)

    @staticmethod
    def encrypt(plain_text):
        """
        RSA 加密，PKCS1_OAEP 模式。

        Args:
          plain_text (str): 明文
        Return:
          str: 加密结果
        """
        try:
            public_key = CryptAsymmetry.import_public_key()
            cryptor = PKCS1_CIPHER.new(public_key)
            encrypted_data = cryptor.encrypt(plain_text.encode('utf-8'))
            crypt_result = b2a_hex(encrypted_data).decode('utf-8').upper()
            return crypt_result
        except Exception as err:
            print('CryptAsymmetry RSA 加密出错')
            raise Exception(err)

    @staticmethod
    def decrypt(crypt_result):
        """
        RSA 解密，PKCS1_OAEP 模式。

        Args:
          crypt_result (str): 加密数据
        Return:
          str: 明文
        """
        try:
            encrypted_data = a2b_hex(crypt_result)
            private_key = CryptAsymmetry.import_private_key()
            cryptor = PKCS1_CIPHER.new(private_key)
            decrypted_data = cryptor.decrypt(encrypted_data)
            plain_text = decrypted_data.decode('utf-8')
            return plain_text
        except Exception as err:
            print('CryptAsymmetry RSA 解密出错')
            raise Exception(err)

    @staticmethod
    def sign(data):
        """
        RSA 签名，PKCS1_PSS模式，采用 SHA1Hash 算法。

        Args:
            data (str): 需要签名的数据
        Return:
            str: 签名
        """
        try:
            private_key = CryptAsymmetry.import_private_key()
            cryptor = PKCS1_SIGNATURE.new(private_key)
            signed_data = cryptor.sign(SHA1Hash(data.encode('utf-8')))
            signature = b2a_hex(signed_data).decode('utf-8').upper()
            return signature
        except Exception as err:
            print('CryptAsymmetry RSA 签名出错')
            raise Exception(err)

    @staticmethod
    def verify(data, signature):
        """
        RSA 验签，PKCS1_PSS模式，采用 SHA1Hash 算法。

        Args:
            data (str): 需验证签名的数据
            signature (str): 目标签名
        Return:
            bool: 验证结果
        """
        try:
            public_key = CryptAsymmetry.import_public_key()
            cryptor = PKCS1_SIGNATURE.new(public_key)
            digest = SHA1Hash(data.encode('utf-8'))
            return cryptor.verify(digest, a2b_hex(signature))
        except Exception as err:
            print('CryptAsymmetry RSA 验签出错')
            raise Exception(err)


class CryptAE:
    """认证加密。 AES 算法，EAX 模式。"""

    @staticmethod
    def encrypt(plain_text, key=AES_KEY):
        """
        AES-EAX 加密。

        Args:
          plain_text (str): 明文
          key (str): 密钥
        Return:
          str: 加密结果
        """
        try:
            header = 'Hello, Worldlet!'
            header = header.encode('utf-8')
            cryptor = AES.new(key.encode('utf-8'), AES.MODE_EAX)
            cryptor.update(header)
            ciphertext, tag = cryptor.encrypt_and_digest(plain_text.encode('utf-8'))
            json_k = ['nonce', 'tag', 'header', 'ciphertext']
            json_v = [b64encode(x).decode('utf-8') for x in [cryptor.nonce, tag, header, ciphertext]]
            crypt_result = json.dumps(dict(zip(json_k, json_v)))
            return crypt_result
        except Exception as err:
            print('CryptAE AES-EAX 加密出错')
            raise Exception(err)

    @staticmethod
    def decrypt(crypt_result, key=AES_KEY):
        """
        AES-EAX 解密。

        Args:
          crypt_result (str): 加密数据
          key (str): 密钥
        Return:
          str: 明文
        """
        try:
            result_dict = json.loads(crypt_result)
            json_k = ['nonce', 'tag', 'header', 'ciphertext']
            jv = {k: b64decode(result_dict[k]) for k in json_k}
            cryptor = AES.new(key.encode('utf-8'), AES.MODE_EAX, nonce=jv['nonce'])
            cryptor.update(jv['header'])
            plain_text = cryptor.decrypt_and_verify(jv['ciphertext'], jv['tag'])
            return plain_text.decode('utf-8')
        except Exception as err:
            print('CryptAE AES-EAX 解密出错')
            raise Exception(err)
