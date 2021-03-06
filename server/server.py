import socket
import threading
import json
import struct
from RSA.RSA_main import RSA_main


class Server:
    def __init__(self):
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__connections = list()
        self.__nicknames = list()
        self.__users_pub_keys = list()

    def __user_thread(self, user_id):
        connection = self.__connections[user_id]
        nickname = self.__nicknames[user_id]

        print('[Server] user', user_id, nickname, '加入聊天室')
        self.__broadcast(message='Usre ' + str(nickname) +
                         '(' + str(user_id) + ')' + ' join')

        while True:
            try:
                buffer = self.__recv_one_message(connection).decode()
                obj = json.loads(buffer)
                if obj['type'] == 'broadcast':
                    self.__broadcast(obj['sender_id'], obj['message'])
                elif obj['type'] == 'sendMessage':
                    jsonByte = json.dumps({
                        'type': obj['type'],
                        'sender_id': obj['sender_id'],
                        'sender_nickname': self.__nicknames[obj['sender_id']],
                        'receiver_d': obj['receiver_id'],
                        'message': obj['message'],
                    }).encode()
                    self.__send_one_message(
                        self.__connections[obj['receiver_id']], jsonByte)
                elif obj['type'] == 'logout':
                    print('[Server] user', user_id, nickname, '退出聊天室')
                    self.__broadcast(
                        message='User ' + str(nickname) + '(' + str(user_id) + ')' + 'exeit')
                    self.__connections[user_id].close()
                    self.__connections[user_id] = None
                    self.__nicknames[user_id] = None
                    self.__users_pub_keys[user_id] = None
                    for i in range(1, len(self.__connections)):
                        if user_id != i and self.__connections[i]:
                            jsonByte = json.dumps({
                                'type': 'logout',
                                'otherUsersPubKey': self.__users_pub_keys
                            }).encode()
                            self.__send_one_message(
                                self.__connections[i], jsonByte)
                    break
                else:
                    print('[Server] 無法解析json資料:',
                          connection.getsockname(), connection.fileno())
            except Exception:
                print('[Server] 連接失效:', connection.getsockname(),
                      connection.fileno())
                self.__connections[user_id].close()
                self.__connections[user_id] = None
                self.__nicknames[user_id] = None

    def __broadcast(self, sender_id=0, message=''):
        for i in range(1, len(self.__connections)):
            self.__sendMessageTo(sender_id, i, message)

    def __send_one_message(self, sock, data):  # input bytes
        length = len(data)
        sock.sendall(struct.pack('!I', length))
        sock.sendall(data)

    def __recvall(self, sock, count):
        buf = b''
        while count:
            newbuf = sock.recv(count)
            if not newbuf:
                return None
            buf += newbuf
            count -= len(newbuf)
        return buf

    def __recv_one_message(self, sock):  # return jsonObject
        lengthbuf = self.__recvall(sock, 4)
        length, = struct.unpack('!I', lengthbuf)
        return self.__recvall(sock, length)

    def __encryptMessage(self, receiver_id, message):
        publicKey = self.__users_pub_keys[receiver_id]
        message = message.encode('UTF-8')
        message = RSA_main(message, publicKey).encrypt()
        return message

    def __sendMessageTo(self, sender_id=0, receiver_id=0, message=''):
        if (self.__connections[receiver_id] != None and sender_id != receiver_id):

            if (sender_id == 0):
                message = self.__encryptMessage(receiver_id, message)

            jsonByte = json.dumps({
                'type': 'sendMessage',
                'sender_id': sender_id,
                'sender_nickname': self.__nicknames[sender_id],
                'message': message
            }).encode()

            self.__send_one_message(self.__connections[receiver_id], jsonByte)

    def __waitForLogin(self, connection):
        try:
            buffer = self.__recv_one_message(connection).decode()
            obj = json.loads(buffer)
            if obj['type'] == 'login':
                self.__connections.append(connection)
                self.__nicknames.append(obj['nickname'])
                self.__users_pub_keys.append(obj['pubkey'])
                jsonByte1 = json.dumps({
                    'id': len(self.__connections) - 1,
                }).encode()

                self.__send_one_message(connection, jsonByte1)

                for userConnection in self.__connections:
                    if (userConnection != None):
                        jsonByte = json.dumps({
                            'type': 'login',
                            'otherUsersPubKey': self.__users_pub_keys
                        }).encode()

                        self.__send_one_message(userConnection, jsonByte)

                thread = threading.Thread(
                    target=self.__user_thread, args=(len(self.__connections) - 1,))
                thread.setDaemon(True)
                thread.start()
            else:
                print('[Server] 無法解析json數據包:',
                      connection.getsockname(), connection.fileno())
        except Exception:
            print('[Server] 無法接受数據:', connection.getsockname(),
                  connection.fileno())

    def start(self):
        self.__socket.bind(('127.0.0.1', 8888))

        self.__socket.listen(10)
        print('[Server] 伺服器正在運行......')

        self.__users_pub_keys.clear()
        self.__connections.clear()
        self.__nicknames.clear()

        self.__connections.append(None)
        self.__nicknames.append('System')
        self.__users_pub_keys.append(None)

        while True:
            connection, address = self.__socket.accept()
            print('[Server] 收到一个新連接', connection.getsockname(),
                  connection.fileno())

            thread = threading.Thread(
                target=self.__waitForLogin, args=(connection,))
            thread.setDaemon(True)
            thread.start()
