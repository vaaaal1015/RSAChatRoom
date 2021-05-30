import random
import math
import struct


class RSA_main:
    def __init__(self, code, key):
        self.code = code
        self.key = key

    def encrypt(self):
        # print("Encrypting...")
        result = bytes()
        for byte in self.code:
            number = (pow(byte, int(self.key[0]))) % int(self.key[1])
            # print(number)
            result += number.to_bytes(5, byteorder="little")
        # return result
        return self.toUTF8(result)

    def toUTF8(self, byte):
        result = str()
        for i in range(len(byte)):
            result += ((byte[i] >> 4).to_bytes(1, byteorder="little")).decode('UTF-8') + \
                ((byte[i] & 0xf).to_bytes(1, byteorder="little")).decode('UTF-8')
        return result

    def splitBytes(self, byte):
        result = bytes()
        for i in range(len(byte)):
            result += (byte[i] >> 4).to_bytes(1, byteorder="little") + \
                (byte[i] & 0xf).to_bytes(1, byteorder="little")
        return result

    def toBytes(self, utf8):
        result = bytes()
        text = utf8.encode('UTF-8')
        for i in range(0, len(text), 2):
            result += ((text[i] << 4) + (text[i + 1])
                       ).to_bytes(1, byteorder="little")
        return result

    def decrypt(self):
        # print("Decrypting...")
        result = bytes()
        self.code = self.toBytes(self.code)
        for i in range(0, len(self.code), 5):
            byte = int.from_bytes(self.code[i: i+5], byteorder='little')
            # print(byte)
            result += ((pow(byte, int(self.key[0]))) % int(
                self.key[1])).to_bytes(2, byteorder="little")
        return result


if __name__ == '__main__':
    import RSA_Algrithm
    aaa = RSA_Algrithm.RSA_Algrithm()
    publicKey, privateKey = aaa.gennerateTwoKeys()
    string = "Hello World"
    # string with encoding 'utf-8'
    # arr = bytes(string, 'utf-8')
    arr = string.encode('UTF-8')
    print(publicKey[1])
    for byte in arr:
        print(byte, end=' ')

    encrypted = RSA_main(arr, publicKey)
    encryptedResult = encrypted.encrypt()
    print(encryptedResult.encode('UTF-8'))

    # print(encrypted.toBytes((b'\x0f\x0f').decode('UTF-8')))

    decrypted = RSA_main(encryptedResult, privateKey)
    decryptedResult = decrypted.decrypt()
    print(decryptedResult)
    print(decryptedResult.decode('UTF-8'))
