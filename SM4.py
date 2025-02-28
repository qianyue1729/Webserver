
##############################################################################
#                                                                            #
#             国产SM4加密，分组加密算法，可用于传输数据加密                      #
#                     bupt+wxy+2021212272                                    #
##############################################################################
from gmssl import sm4


class SM4():
    """
    国产加密算法： sm4加解密
    """

    def __init__(self):
        self.gmsm4 = sm4.CryptSM4()  # 实例化

    def encryptSM4(self, encrypt_key, value):
        """
        国密sm4加密
        :param encrypt_key: sm4加密key(十六进制字符)
        :param value: 待加密的字符串
        :return: sm4加密后的十六进制字符
        """
        gmsm4 = self.gmsm4
        gmsm4.set_key(bytes.fromhex(encrypt_key), sm4.SM4_ENCRYPT)  # 设置密钥，将十六进制字符Key转为十六进制字节
        data_str = str(value)
        encrypt_value = gmsm4.crypt_ecb(data_str.encode())  # ecb模式开始加密，encode():普通字符转为字节
        return encrypt_value.hex()  # 返回十六进制字符

    def decryptSM4(self, decrypt_key, encrypt_value):
        """
        国密sm4解密
        :param decrypt_key:sm4加密key(十六进制字符)
        :param encrypt_value: 待解密的十六进制字符
        :return: 原字符串
        """
        gmsm4 = self.gmsm4
        gmsm4.set_key(bytes.fromhex(decrypt_key), sm4.SM4_DECRYPT)  # 设置密钥，将十六进制字符Key转为十六进制字节
        decrypt_value = gmsm4.crypt_ecb(bytes.fromhex(encrypt_value))  # ecb模式开始解密。bytes.fromhex():十六进制字符转为十六进制字节
        return decrypt_value.decode()


if __name__ == '__main__':
    key = input("请输入你要使用的密钥(十六进制)：")    # 密钥
    strData = input("请输入需要加密的明文")   # 明文
    SM4 = SM4()
    print("原字符", strData)
    encData = SM4.encryptSM4(key, strData)  # 加密后的数据
    print("sm4加密结果", encData)

    decData = SM4.decryptSM4(key, encData)
    print("sm4解密结果", decData)  # 解密后的数据