# import RSA_Algrithm
import random
import math
import struct


class RSA_main:
    def __init__(self, code, key):
        self.code = code
        self.key = key

    def encrypt(self):
        print("Encrypting...")
        # result = []
        # for byte in self.code:
        #     result.append((pow(byte, int(self.key[0]))) % int(self.key[1]))
        #     print((result[-1]).to_bytes(5, byteorder="little"))
        # return result
        result = bytes()
        for byte in self.code:
            number = (pow(byte, int(self.key[0]))) % int(
                self.key[1])
            print(number)
            result += number.to_bytes(5, byteorder="little")
        return result

    def decrypt(self):
        # result = []
        print("Decrypting...")
        # print(type(self.code))
        # print(len(self.code))
        result = bytes()

        for i in range(0, len(self.code), 5):
            byte = int.from_bytes(self.code[i: i+5], byteorder='little')
            print(byte)
            result += ((pow(byte, int(self.key[0]))) % int(
                self.key[1])).to_bytes(2, byteorder="little")
        return result
        # return None


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
    print(encryptedResult)

    decrypted = RSA_main(encryptedResult, privateKey)
    decryptedResult = decrypted.decrypt()
    print(decryptedResult.decode('UTF-8'))
