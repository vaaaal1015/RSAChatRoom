import struct
import base64

# testBytes = b'\xe4\xbd\xa0'
# testResult = struct.unpack('BBB', testBytes)
# print(testResult)
# print(testBytes.decode('utf-8'))

# testStr = '你'.encode('utf-8')

# for p in testStr:
#     print('%x' % (p))


print(base64.b64encode("h"))
