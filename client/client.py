import socket
import threading
import json
import struct
from cmd import Cmd
from RSA.RSA_main import RSA_main
from RSA.RSA_Algrithm import RSA_Algrithm


class Client(Cmd):
    prompt = ''
    intro = '[Welcome] 簡易聊天室客户端\n' + '[Welcome] 输入help来獲得幫助\n'

    def __init__(self):
        super().__init__()
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__id = None
        self.__nickname = None
        self.__isLogin = False
        self.__pubKey, self.__privKey = RSA_Algrithm().gennerateTwoKeys()
        self.__usersPubKey = list()

    def __receive_message_thread(self):
        while self.__isLogin:
            try:
                buffer = self.__recv_one_message(self.__socket).decode()
                obj = json.loads(buffer)
                if (obj['type'] == 'login' or obj['type'] == 'logout'):
                    self.__usersPubKey = obj['otherUsersPubKey']
                else:
                    print('[' + str(obj['sender_nickname']) + '(' + str(obj['sender_id']
                                                                        ) + ')' + ']', self.__decryptMessage(obj['message']))
            except Exception:
                print('[Client] 無法從伺服器獲取數據')

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
        publicKey = self.__usersPubKey[receiver_id]
        message = message.encode('UTF-8')
        message = RSA_main(message, publicKey).encrypt()
        return message

    def __decryptMessage(self, message):
        message = RSA_main(message, self.__privKey).decrypt()
        message = message.decode('UTF-8')
        return message

    def __send_message_thread(self, message):
        for receiver_id in range(len(self.__usersPubKey)):
            if (receiver_id != self.__id and self.__usersPubKey[receiver_id] != None):
                mesg = ''
                mesg = self.__encryptMessage(receiver_id, message)
                jsonByte = json.dumps({
                    'type': 'sendMessage',
                    'sender_id': self.__id,
                    'receiver_id': receiver_id,
                    'message': mesg
                }).encode()

                self.__send_one_message(self.__socket, jsonByte)

    def __send_message_by_id_thread(self, receiver_id, message):
        if (receiver_id != self.__id and self.__usersPubKey[receiver_id] != None):
            mesg = ''
            mesg = self.__encryptMessage(receiver_id, message)
            jsonByte = json.dumps({
                'type': 'sendMessage',
                'sender_id': self.__id,
                'receiver_id': receiver_id,
                'message': mesg
            }).encode()
            self.__send_one_message(self.__socket, jsonByte)

    def start(self):
        self.__socket.connect(('127.0.0.1', 8888))
        self.cmdloop()

    def do_login(self, args):
        nickname = args.split(' ')[0]

        jsonByte = json.dumps({
            'type': 'login',
            'nickname': nickname,
            'pubkey': self.__pubKey
        }).encode()

        self.__send_one_message(self.__socket, jsonByte)

        try:
            buffer = self.__recv_one_message(self.__socket).decode()
            obj = json.loads(buffer)

            if obj['id']:
                self.__nickname = nickname
                self.__id = obj['id']
                self.__isLogin = True
                print('[Client] 成功登入到聊天室')

                thread = threading.Thread(target=self.__receive_message_thread)
                thread.setDaemon(True)
                thread.start()
            else:
                print('[Client] 無法登入到聊天室')
        except Exception:
            print('[Client] 無法從伺服器獲取數據')

    def do_send(self, args):
        message = args
        print('[' + str(self.__nickname) +
              '(' + str(self.__id) + ')' + ']', message)
        thread = threading.Thread(
            target=self.__send_message_thread, args=(message,))
        thread.setDaemon(True)
        thread.start()

    def do_sid(self, args):
        id = int(args.split(' ')[0])
        message = args.split(' ', 1)[1]
        print('[' + str(self.__nickname) +
              '(' + str(self.__id) + ')' + ']', message)
        thread = threading.Thread(
            target=self.__send_message_by_id_thread, args=(id, message,))
        thread.setDaemon(True)
        thread.start()

    def do_logout(self, args=None):
        jsonByte = json.dumps({
            'type': 'logout',
            'sender_id': self.__id
        }).encode()
        self.__send_one_message(self.__socket, jsonByte)
        self.__isLogin = False
        return True

    def do_help(self, arg):
        command = arg.split(' ')[0]
        if command == '':
            print('[Help] login nickname - 登入到聊天室，nickname是你選擇的暱稱')
            print('[Help] send message - 發送訊息，message是你输入的訊息')
            print('[Help] sid id message - 發送訊息，id是你發送訊息的對象，message是你输入的訊息')
            print('[Help] logout - 退出聊天室')
        elif command == 'login':
            print('[Help] login nickname - 登入到聊天室，nickname是你選擇的暱稱')
        elif command == 'send':
            print('[Help] send message - 發送訊息，message是你输入的訊息')
        elif command == 'sid':
            print('[Help] sid id message - 發送訊息，id是你發送訊息的對象，message是你输入的訊息')
        elif command == 'logout':
            print('[Help] logout - 退出聊天室')
        else:
            print('[Help] 没有查尋到你想要了解的指令')
