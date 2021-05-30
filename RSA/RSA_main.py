import RSA_Algrithm
import random
import math
class RSA_main:
    def __init__(self, code, key):
        self.code = code
        self.key = key
    def encrypt(self):
        print("Encrypting...")
        result = []
        for byte in self.code:
            result.append((pow(byte,int(self.key[0])))%int(self.key[1]))
        return result
    def decrypt(self):
        result = []
        print("Decrypting...")
        for byte in self.code:
            result.append((pow(byte,int(self.key[0])))%int(self.key[1]))
        return result

""" def main():
    aaa = RSA_Algrithm.RSA_Algrithm()
    publicKey, privateKey = aaa.gennerateTwoKeys()
    string = "Hello World"
    # string with encoding 'utf-8'
    arr = bytes(string, 'utf-8')
    for byte in arr:
        print(byte, end=' ')
    encrypted = RSA_main(arr, publicKey)
    encryptedResult = encrypted.encrypt()
    print(encryptedResult)
    decrypted = RSA_main(encryptedResult, privateKey)
    decryptedResult = decrypted.decrypt()
    print(decryptedResult)
main() """
    