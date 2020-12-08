import sys
import getopt
import socket
import ip_parser
from pyngrok import ngrok
from threading import Thread

username = ""
clients_set = set()
clients_map = {}
registered = {"chrysalis:fcf8f0af75f80c3fffb0304777eadc00d062264971b902751f90a54d26e21ac4",  # braude
              "ron:da2f073e06f78938166f247273729dfe465bf7e46105c13ce7cc651047bf0ca4",  # crypto
              "tal:13f782f26a407b2888a0942711c239a5e21b93c860ca211981fd762a8c51a1ee",  # totler
              "dima:d2efaa6dd6ae6136c19944fae329efd3fb2babe1e6eec26982a422aa60d222b8"}  # ari

class ClientHandler(Thread):
    def __init__(self, addr, username, upload_destination=None):
        Thread.__init__(self)
        self.addr = addr
        self.username = username
        self.upload_destination = upload_destination if upload_destination else f'chat.txt'

    def run(self):
        message = ""
        broadcast(f"Welcome aboard {self.username}!")
        while message != "{quit}":
            message = self.receive()
            broadcast(f"{self.username}: {message.replace('{quit}', 'left')}")
            if self.upload_destination:
                with open(self.upload_destination, 'a') as f:
                    print(f"{self.username} says: {message}")
                    f.write(f"{self.username} says: {message}\n")
        clients_map[self.username].send(bytes("Hasta la vista, baby", 'utf8'))
        clients_set.remove(self.username)
        clients_map.pop(self.username)

    def receive(self):
        return clients_map[self.username].recv(1024).decode("utf8")

def broadcast(msg):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    for sock in clients_set:
        clients_map[sock].send(bytes(msg, "utf8"))

def server_loop(target, port, upload_dest, external_addr, external_port):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target = target if target else '127.0.0.1'
        target = target if target != "my-ip" else ip_parser.myip()
        port = port if port else 33000
        server.bind((target, port))
        print(f'[*] Bound {external_addr}:{external_port}')
        server.listen(5)
        print(f'[*] Listen {external_addr}:{external_port}')
        while True:
            client, addr = server.accept()
            print(f"[*] Successfully connected {addr[0]}:{addr[1]}")
            while not is_valid(client):
                client.send(bytes("Username and/or password are incorrect, please repeat", "utf8"))
            clients_set.add(username)
            clients_map[username] = client
            client.send(bytes('{granted}', "utf8"))
            client_thread = ClientHandler(addr, username, upload_dest)
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[!] Aborting connection...")
        server.close()


def is_valid(client):
    global username
    login = client.recv(1024).decode()
    username = login.split(":")[0]
    return login in registered and username not in clients_set


def usage():
    print("-h --help                Invoke this help page")
    print("-l --listen=ip:port      Listen for clients on host (default = 127.0.0.1:33000)")
    print("-u --upload=destination  Upload destination")
    sys.exit()


def main():
    port = 0
    target = ""
    upload_destination = ""
    try:
        if not sys.argv[1:]:
            target = "127.0.0.1"
            port = 33000
            print("Used default arguments")
        opts, args = getopt.getopt(sys.argv[1:], "hu:l:", ["help", "listen=", "upload="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-l", "--listen"):
            target = a.split(":")[0]
            port = int(a.split(":")[1])
        elif o in ("-u", "--upload"):
            upload_destination = a
        else:
            assert False, "Unexpected argument"
    assert "Wrong arguments set. Type --help for more information."

    if target and port > 0:
        ngrok.set_auth_token("1lByfcid7kPCkpyp0cpJ5eGIJgW_2jJfbZbA41rQLYwiSqLK1")
        tcp_tunnel = ngrok.connect(33000, "tcp")
        external_name = tcp_tunnel.public_url[6:].split(':')
        external_addr = socket.getaddrinfo(external_name[0], None)[0][4][0]
        server_loop(target, port, upload_destination, external_addr, external_name[1])
    else:
        print("[*] Exception! Exiting...")


if __name__ == '__main__':
    main()
