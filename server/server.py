import socket
import threading
import json
import base64
import rsa
from rsa import PublicKey


class Server:
    """
    服务器类
    """

    def __init__(self):
        """
        构造
        """
        self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.__connections = list()
        self.__nicknames = list()
        self.__users_pub_keys = list()
    def __user_thread(self, user_id):
        """
        用户子线程
        :param user_id: 用户id
        """
        connection = self.__connections[user_id]
        nickname = self.__nicknames[user_id]

        print('[Server] 用户', user_id, nickname, '加入聊天室')
        self.__broadcast(message='用户 ' + str(nickname) + '(' + str(user_id) + ')' + '加入聊天室')

        # 侦听
        while True:
            # noinspection PyBroadException
            try:
                buffer = connection.recv(1024).decode()
                # 解析成json数据
                obj = json.loads(buffer)
                # 如果是广播指令
                if obj['type'] == 'broadcast':
                    self.__broadcast(obj['sender_id'], obj['message'])
                elif obj['type'] == 'logout':
                    print('[Server] 用户', user_id, nickname, '退出聊天室')
                    self.__broadcast(message='用户 ' + str(nickname) + '(' + str(user_id) + ')' + '退出聊天室')
                    self.__connections[user_id].close()
                    self.__connections[user_id] = None
                    self.__nicknames[user_id] = None
                    self.__users_pub_keys[user_id] = None
                    for i in range(1, len(self.__connections)):
                        if user_id != i and self.__connections[i]:
                            self.__connections[i].send(json.dumps({
                                'type': 'logout',
                                'otherUsersPubKey':self.__users_pub_keys
                            }).encode())
                    break
                else:
                    print('[Server] 无法解析json数据包:', connection.getsockname(), connection.fileno())
            except Exception:
                print('[Server] 连接失效:', connection.getsockname(), connection.fileno())
                self.__connections[user_id].close()
                self.__connections[user_id] = None
                self.__nicknames[user_id] = None

    def __broadcast(self, sender_id=0, message=''):
        for i in range(len(self.__connections)):
            self.__sendMessageTo(sender_id, i, message)


    def __packMessage(self, receiver_id, message):
        n = self.__users_pub_keys[receiver_id][0]
        e = self.__users_pub_keys[receiver_id][1]
        message = rsa.encrypt(message.encode('UTF-8'), PublicKey(n, e))
        b64_mesg = base64.b64encode(message)
        mesg = b64_mesg.decode('UTF-8')
        return mesg

    def __sendMessageTo(self, sender_id=0, receiver_id=0, message=''):
        """
        广播
        :param user_id: 用户id(0为系统)
        :param message: 广播内容
        """
        if (self.__connections[receiver_id] != None and sender_id != receiver_id):

            if (sender_id == 0):
                message = self.__packMessage(receiver_id, message)

            self.__connections[receiver_id].send(json.dumps({
                'type': 'sendMessage',
                'sender_id': sender_id,
                'sender_nickname': self.__nicknames[sender_id],
                'receiver_id': receiver_id,
                'receiver_nickname': self.__nicknames[receiver_id],
                'message': message
            }).encode())

    def __turnPubKeyToList(self, pubKey):
        n = pubKey['n']
        e = pubKey['e']
        return [n, e]


    def __waitForLogin(self, connection):
        # 尝试接受数据
        # noinspection PyBroadException
        try:
            buffer = connection.recv(1024).decode()
            # 解析成json数据
            obj = json.loads(buffer)
            # 如果是连接指令，那么则返回一个新的用户编号，接收用户连接
            if obj['type'] == 'login':
                self.__connections.append(connection)
                self.__nicknames.append(obj['nickname'])
                self.__users_pub_keys.append(obj['pubkey'])
                connection.send(json.dumps({
                    'id': len(self.__connections) - 1,
                }).encode())

                for userConnection in self.__connections:
                    if (userConnection != None):
                        userConnection.send(json.dumps({
                            'type': 'login',
                            'otherUsersPubKey': self.__users_pub_keys
                        }).encode())

                # 开辟一个新的线程
                thread = threading.Thread(target=self.__user_thread, args=(len(self.__connections) - 1,))
                thread.setDaemon(True)
                thread.start()
            else:
                print('[Server] 无法解析json数据包:', connection.getsockname(), connection.fileno())
        except Exception:
            print('[Server] 无法接受数据:', connection.getsockname(), connection.fileno())

    def start(self):
        """
        启动服务器
        """
        # 绑定端口
        self.__socket.bind(('127.0.0.1', 8888))
        # 启用监听
        self.__socket.listen(10)
        print('[Server] 服务器正在运行......')

        # 清空连接
        self.__users_pub_keys.clear()
        self.__connections.clear()
        self.__nicknames.clear()
        self.__connections.append(None)
        self.__nicknames.append('System')
        self.__users_pub_keys.append(None)
        # 开始侦听
        while True:
            connection, address = self.__socket.accept()
            print('[Server] 收到一个新连接', connection.getsockname(), connection.fileno())

            thread = threading.Thread(target=self.__waitForLogin, args=(connection,))
            thread.setDaemon(True)
            thread.start()
