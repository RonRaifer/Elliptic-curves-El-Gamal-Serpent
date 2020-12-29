import os
import sys
import getopt
import socket
import threading
import tkinter
import hashlib
import json

from ecc import ECPoint
from elgamal import ElGamal as eg
from serpent import Serpent as serp
from threading import Thread, Event

Return = "<Return>"

class ClientSender(Thread):
    def __init__(self, client, target, port):
        Thread.__init__(self)
        self.port = port
        self.client = client
        self.target = target
        self.elgamal = eg()
        self.serpent = serp()
        self.first = False
        self.screen = None
        self.my_msg = None
        self.priv_key = None
        self.msg_list = None
        self.username = None
        self.key_flag = Event()
        self.chat_flag = Event()
        self.login_flag = Event()

        Thread(target=self.receiver).start()
        self.login_window()

    def run(self):
        try:
            self.client.connect((self.target, self.port))
            print(f'Connected {self.target}:{self.port}')
        except Exception as err:
            print(err)
            print('[!] Exception! Exiting...')
            self.client.close()

    def login_window(self):
        global username_verify, password_verify, username_field, password_field  # , key_field, key_verify
        self.screen = tkinter.Tk()
        self.screen.geometry("280x150")
        self.screen.title("CRYPT0CH4T Login")
        self.screen.protocol("WM_DELETE_WINDOW", self.on_closing)
        tkinter.Label(self.screen, text="Please enter details below to login").pack()
        username_verify = tkinter.StringVar()
        password_verify = tkinter.StringVar()
        tkinter.Label(self.screen, text="Username * ").pack()
        username_field = tkinter.Entry(self.screen, textvariable=username_verify)
        username_field.pack()
        tkinter.Label(self.screen, text="Password * ").pack()
        password_field = tkinter.Entry(self.screen, textvariable=password_verify, show='*')
        password_field.pack()
        password_field.bind(Return, self.login_verifier)
        tkinter.Label(self.screen).pack()
        tkinter.Button(self.screen, text="Login", width=10, height=1, command=self.login_verifier).pack()
        tkinter.mainloop()

    def login_verifier(self, event=None):
        self.username = username_verify.get()
        username_field.delete(0, tkinter.END)
        password1 = password_verify.get()
        h = hashlib.sha256()
        h.update(password1.encode())
        password1 = h.hexdigest()
        password_field.delete(0, tkinter.END)
        self.sender({
            "message": "details",
            "username": self.username,
            "password": password1
        })
        self.login_flag.wait(timeout=15)
        self.login_flag.clear()
        self.screen.destroy()
        if self.first:
            self.key_window()
        else:
            self.chat_window()

    def key_verifier(self, event=None):
        self.priv_key = key_verify.get()
        key_field.delete(0, tkinter.END)
        self.key_flag.wait(timeout=15)
        self.key_flag.clear()
        self.screen.destroy()
        self.chat_window()

    def key_window(self):
        global key_verify, key_field
        self.screen = tkinter.Tk()
        self.screen.geometry("280x150")
        self.screen.title("CRYPT0CH4T Key setup")
        self.screen.protocol("WM_DELETE_WINDOW", self.on_closing)
        tkinter.Label(self.screen, text="Please enter details for encryption").pack()
        key_verify = tkinter.StringVar()
        tkinter.Label(self.screen, text="Encryption key * ").pack()
        key_field = tkinter.Entry(self.screen, textvariable=key_verify)
        key_field.pack()
        key_field.bind(Return, self.key_verifier)
        tkinter.Label(self.screen).pack()
        tkinter.Button(self.screen, text="Set key", width=10, height=1, command=self.key_verifier).pack()
        tkinter.mainloop()

    def sender(self, message):
        self.client.send(bytes(json.dumps(message).encode()))

    def receiver(self):
        json_packet = {
            "message": bytes("Empty default message", encoding='utf8').hex()
        }
        while True:
            try:
                message = self.client.recv(1024).decode()
                if len(message) == 0:
                    raise NotImplementedError
                # 1) Split messages on packets
                for str_packet in message.split("}{"):
                    print(str_packet)
                    if not str_packet.endswith('}'):
                        str_packet += '}'
                    if str_packet[0] != '{':
                        str_packet = '{' + str_packet
                    json_packet = json.loads(str_packet)
                    if json_packet["from"] == "server":
                        # 2) Login step
                        if json_packet['message'] == '{provide}':
                            self.first = json_packet["first"]
                            # 1.1) User sends his public part of ECC to others
                            self.sender({
                                "message": "{multiplier}",
                                "EGn": self.elgamal.n
                            })
                            if self.first:
                                self.login_flag.set()
                        # 3) Others receive your key from server
                        elif json_packet['message'] == "{ecc-key}":
                            self.elgamal.keygen(json_packet["EGn"])
                        # 3) On granted you receive a whole previous public key w\ your part
                        elif json_packet['message'] == "{granted}":
                            self.elgamal.keygen(json_packet["EGn"])
                            self.key_flag.set()
                            self.login_flag.set()
                        # 4) Receive encrypted key for chat and try to decrypt
                        elif json_packet['message'] == "{secret key}":
                            ECP = ECPoint(json_packet['ECPoint']['x'],
                                          json_packet['ECPoint']['y'],
                                          json_packet['ECPoint']['inf'])
                            self.priv_key = bytes().fromhex(json_packet['key'])
                            self.priv_key = self.elgamal.decrypt((ECP, self.priv_key)).decode()
                        # 5) Everyone got message about new client
                        else:
                            if json_packet["message"].split()[0] == "Welcome":
                                if self.first and json_packet["message"].split()[2] != f"{self.username}!":
                                    self.encrypt_and_send()
                                while not self.chat_flag.is_set():
                                    continue
                            if self.chat_flag.is_set():
                                self.msg_list.insert(tkinter.END, json_packet['message'])
                            else:
                                print(str_packet)
                            if json_packet["message"].split()[1] == "left":
                                raise ConnectionAbortedError
                    else:
                        name = json_packet['from']
                        json_packet = json.loads(bytes().fromhex(json_packet['message']).decode())
                        length = json_packet['length']
                        b_msg = bytes().fromhex(json_packet['message'])
                        decrypted_message = serp.decrypt(b_msg, self.priv_key)[16 - length:]
                        self.msg_list.insert(tkinter.END, f"{name}: {decrypted_message}")
            except UnicodeDecodeError as e:
                decrypted_message = bytes().fromhex(json_packet['message']).decode('utf8', errors='replace')
                self.msg_list.insert(tkinter.END, f"{json_packet['from']}: {decrypted_message}")
            except json.decoder.JSONDecodeError as e:
                print(e, json_packet)
            except (ConnectionError, NotImplementedError) as e:
                self.client.close()
                exit()

    def encrypt_and_send(self):
        # 1) Prepare serpent key for sending
        key = self.priv_key.encode('utf8')
        # 2) Encrypt with elgamal ecc
        key = self.elgamal.encrypt(key)
        # 3) Send to the server with public key part
        self.sender({
            "message": "{secret key}",  # message
            "ECPoint": {    # Encrypted serpent key
                "x": key[0].x,
                "y": key[0].y,
                "inf": key[0].inf
            },
            "key": key[1].hex()
        })

    def safety_sender(self, event=None):
        """Handles sending of messages."""
        # 1) Cut message, serpent doesn't support long messages
        message = self.my_msg.get()[:16].encode()
        # 2) Build packet with length, msg and it's hash
        packet = json.dumps({
            "length": len(message),
            "message": serp.encrypt(bytes(message), self.priv_key).hex(),
            "hash":  hash(message)
        }).encode()
        # 3) Clear input field and send
        self.my_msg.set("")
        self.client.send(packet)

    def chat_window(self):
        self.screen = tkinter.Tk()
        self.screen.title("CRYPT0CH4T")
        self.screen.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.screen = tkinter.Frame(self.screen)
        self.my_msg = tkinter.StringVar()  # For the messages to be sent.
        self.my_msg.set("Type your messages here.")
        scrollbar = tkinter.Scrollbar(self.screen)  # To navigate through past messages.
        # Following will contain the messages.
        self.msg_list = tkinter.Listbox(self.screen, height=30, width=55, font=12, bd=8, yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
        self.msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
        self.msg_list.pack()
        self.screen.pack()
        entry_field = tkinter.Entry(textvariable=self.my_msg, width=55, font=10, bd=5)
        entry_field.bind(Return, self.safety_sender)
        entry_field.pack()
        self.chat_flag.set()
        tkinter.mainloop()

    def on_closing(self, event=None):
        """This function is to be called when the window is closed."""
        self.client.close()
        self.screen.destroy()
        quit()


def usage():
    print("-h --help                    Invoke this help page")
    print("-c --connect=ip:port         IP:Port connect to")


def main():
    opts = []
    port = 33000
    target = "127.0.0.1"
    client = None
    try:
        if not sys.argv[1:]:
            usage()
            sys.exit()
        opts, args = getopt.getopt(sys.argv[1:], "hc:", ["help", "connect="])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
        elif o in ("-c", "--connect"):
            target = a.split(":")[0]
            port = int(a.split(":")[1])
        else:
            assert False, "Unexpected argument"
    assert "Wrong arguments set. Type --help for more information."
    try:
        if target and port > 0:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((target, port))
            print(f'Connected {target}:{port}')
            ClientSender(client, target, port)
        else:
            print("[*] Exception! Exiting...")
    except Exception as err:
        print(err)
        print('[!] Exception! Exiting...')
        client.close()


if __name__ == '__main__':
    main()
    print("DONE")
