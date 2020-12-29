import json
import sys
import getopt
import socket
import ip_parser
import ngrok_token
from pyngrok import ngrok
from threading import Thread, Event

username = ""
clients_set = set()
clients_map = {}

prev_pub_key = 1
temp_pub_key = 1
key_flag = Event()

class ClientHandler(Thread):
    def __init__(self, addr, username, upload_destination=None):
        Thread.__init__(self)
        self.addr = addr
        self.username = username
        self.upload_destination = upload_destination or './chat.txt'

    def run(self):
        broadcast({"from": "server", "message": f"Welcome aboard {self.username}!"})
        try:
            with open(self.upload_destination, 'a') as f:
                while True:
                    try:
                        str_message = clients_map[self.username].recv(1024)
                        if len(str_message) > 0:
                            json_message = json.loads(str_message.decode())
                        else:
                            raise ConnectionError
                        if json_message['message'] == "{secret key}":
                            broadcast({"from": "server",
                                       "message": "{secret key}",
                                       "ECPoint": json_message["ECPoint"],
                                       "key": json_message["key"]})
                        else:
                            broadcast({"from": self.username, "message": str_message.hex()})
                            print(f"{self.username} says: {str_message}")
                        if self.upload_destination:
                            f.write(f"{self.username} says: {str_message}\n")
                    except (UnicodeDecodeError,
                            json.decoder.JSONDecodeError) as e:
                        str_message = str_message.decode("utf8", errors="ignore")
                        print(e, str_message)
        except ConnectionError:
            clients_set.remove(self.username)
            broadcast({"from": "server", "message": f"{self.username} left"})
            clients_map[self.username].close()
            clients_map.pop(self.username)
            print(f"[!] {self.username} left")

def broadcast(msg):  # prefix is for name identification.
    """Broadcasts a message to all the clients."""
    for sock in clients_set:
        try:
            clients_map[sock].send(bytes(json.dumps(msg).encode('utf8')))
        except RuntimeError:
            print(msg)

def server_loop(target, port, upload_dest, external_addr, external_port):
    global server, message, prev_pub_key, temp_pub_key
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
            try:
                # 1) User connect
                client, addr = server.accept()
                print(f"[*] Successfully connected {addr[0]}:{addr[1]}")
                # 2) Check username and login details
                while not is_valid(client):
                    client.send(bytes(json.dumps({
                        "from": "server",
                        "message": "Username and/or password are incorrect, please repeat"
                    }), "utf8"))
                # 3) Ask for serpent key
                client.send(bytes(json.dumps({
                    "from": "server",
                    "message": "{provide}",
                    "first": len(clients_set) == 0
                }), 'utf8'))
                # 4) Receive ECC key
                str_message = client.recv(1024).decode()
                print(str_message)
                json_message = json.loads(str_message)
                # 5) Broadcast ECC key
                if json_message['message'] == "{multiplier}":
                    temp_pub_key = json_message['EGn']
                    broadcast({
                        "from": "server",
                        "message": "{ecc-key}",
                        "key_owner": username,
                        "EGn": json_message['EGn']
                    })
                # 6) Save client in map {username: client}
                clients_map[username] = client
                clients_set.add(username)
                client.send(bytes(json.dumps({
                    "from": "server",
                    "message": "{granted}",
                    "EGn": prev_pub_key
                }), 'utf8'))
                prev_pub_key *= temp_pub_key
                client_thread = ClientHandler(addr, username, upload_dest)
                client_thread.start()
            except (ConnectionError,
                    json.decoder.JSONDecodeError) as e:
                print(e, f"\n[!] Client Aborted connection...")
    except KeyboardInterrupt as e:
        print(e, "\n[!] Aborting connection...")
        clients_map.pop(username)
        server.close()



registered = {
    "kostya": "fcf8f0af75f80c3fffb0304777eadc00d062264971b902751f90a54d26e21ac4",  # braude
    "ron": "da2f073e06f78938166f247273729dfe465bf7e46105c13ce7cc651047bf0ca4",  # crypto
    "tal": "2d9fc5715ed5b94a230884cee901c7ab178e7517a27e6d1c15830413d2e35610",  # kotler
    "dima": "d2efaa6dd6ae6136c19944fae329efd3fb2babe1e6eec26982a422aa60d222b8"  # ari
}

def is_valid(client):
    global username
    try:
        msg = client.recv(1024).decode()
        msg = json.loads(msg)
        username = msg['username']
        password = msg['password']
        return username in registered.keys() and \
               password == registered[username] and \
               username not in clients_set
    except (KeyError,
            TypeError,
            IndexError,
            ConnectionError,
            json.decoder.JSONDecodeError) as e:
        print(e, "\n[!] Please repeat...")
        return False


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
        ngrok.set_auth_token(f"{ngrok_token.token}")
        tcp_tunnel = ngrok.connect(33000, "tcp")
        external_name = tcp_tunnel.public_url[6:].split(':')
        external_addr = socket.getaddrinfo(external_name[0], None)[0][4][0]
        server_loop(target, port, upload_destination, external_addr, external_name[1])
    else:
        print("[*] Exception! Exiting...")


if __name__ == '__main__':
    main()
