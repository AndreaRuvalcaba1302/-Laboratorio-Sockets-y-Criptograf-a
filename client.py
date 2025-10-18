import sys
import socket
import threading
import cryptoutils

SYMMETRIC_KEY = b'A9s9u_X_J5eB1oP7qW3zR0vI8yF4cT2lK7gD4hE6mG2fC0bA='

class chat_client:
    def __init__(self, usr, addr, port, secure):
        self.username = usr
        self.address = addr
        self.port = port
        self.socket = None

        self.secure = secure
        self.cu = cryptoutils.CryptoUtils()
    def connect(self):
        self.socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
        self.socket.connect((self.address, self.port))
        print(f'Connecting to {self.address}:{self.port}')
        listener = threading.Thread(target=self.listen)
        listener.daemon = True
        listener.start()

        self.send()

    def listen(self):
        while True:
            data = self.socket.recv(2048)
            
            if self.secure:
                data = self.cu.descifrar_simetrico(data, SYMMETRIC_KEY) 
            else:
                data = data.decode()
                
            if not data: break
            print(data)

    def send(self):
        print('Enter Ctrl+C to exit ...')
        print('Enter a message:')
        try:
            while True:
                data = input()
                data = self.username + ': ' + data
                
                if self.secure:
                    data = self.cu.cifrar_simetrico(data, SYMMETRIC_KEY)
                else:
                    data = bytearray(data, 'utf-8')
                    
                self.socket.sendall(data)
        except KeyboardInterrupt:
            print('\nClosing connection ...')
            self.socket.close()

if __name__ == '__main__':
    if len(sys.argv) == 4:
        usr = input('Enter your username: ')
        addr = sys.argv[1]
        port = int(sys.argv[2])
        secure = True if sys.argv[3] == '1' else False
        client = chat_client(usr, addr, port, secure)
        client.connect()
    else:
        print('Not enough parameters')