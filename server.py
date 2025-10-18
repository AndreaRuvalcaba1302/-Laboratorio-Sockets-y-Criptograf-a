import sys
import socket
import threading
import cryptoutils

SYMMETRIC_KEY = b'A9s9u_X_J5eB1oP7qW3zR0vI8yF4cT2lK7gD4hE6mG2fC0bA=' 

class chat_server:
    def __init__(self, addr='localhost', port=60500, max_conn=5, secure=False):
        self.address = addr
        self.port = port
        self.max_connections = max_conn
        self.clients = []
        self.cu = cryptoutils.CryptoUtils()
        self.secure = secure

    def handle_client(self, client_socket, client_address):
        self.clients.append((client_socket, client_address))
        print(f'Connected by ', client_address)
        try:
            while True:
                data = client_socket.recv(2048) 
                if not data: break
                if self.secure:
                    data = self.cu.descifrar_simetrico(data, SYMMETRIC_KEY) 
                else:
                    data = data.decode()
                    
                print(data)
                self.broadcast(data, client_socket)

        except Exception as e:
            print(f'Error {e} with client {client_address}')
        finally:
            client_socket.close()
            if (client_socket, client_address) in self.clients:
                self.clients.remove((client_socket, client_address))
            print(f"Cliente {client_address} desconectado")

    def start(self):
        with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as server:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((self.address, self.port))
            server.listen(self.max_connections)
            print(f'✅ Listening on {self.address}:{self.port}')

            while True:
                conn, addr = server.accept()
                print(f'✅ New client connected {addr}')
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr)
                )
                client_thread.start()

    def broadcast(self, message, sender_socket):
        """Envía mensaje a todos los clientes excepto al remitente"""
        for client, addr in self.clients:
            if client != sender_socket:
                try:
                    if self.secure:
                        message_c = self.cu.cifrar_simetrico(message, SYMMETRIC_KEY) 
                    else:
                        message_c = bytearray(message, 'utf-8')
                    client.sendall(message_c)
                except Exception as e:
                    print(f'There was an exceptiom: {e}')
                    self.clients.remove((client, addr))


if __name__ == '__main__':
    if len(sys.argv) == 5:
        addr = sys.argv[1]
        port = int(sys.argv[2])
        max_conn = int(sys.argv[3])
        secure = True if sys.argv[4] == '1' else False
        chat = chat_server(addr, port, max_conn, secure)
        try:
            if secure : print('Starting server in secure mode...')
            else: print('Starting server UNSECURE ...')
            print('Enter Ctrl+C to exit ...')
            chat.start()
        except KeyboardInterrupt:
            print('\nClosing server ...')

    else:
        print('Not enough parameters: address port connections')