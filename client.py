import sys
import getopt
import socket
import tkinter
import hashlib
from threading import Thread

class ClientSender(Thread):
    def __init__(self, client, target, port):
        Thread.__init__(self)
        self.client = client
        self.target = target
        self.logged = False
        self.port = port
        self.top = None
        self.screen = None
        self.my_msg = None
        self.msg_list = None
        self.login_window()

    def run(self):
        try:
            self.client.connect((self.target, self.port))
            print(f'Connected {self.target}:{self.port}')
        except Exception as err:
            print(err)
            print('[!] Exception! Exiting...')
            self.client.close()

    def receive(self):
        while True:
            message = self.client.recv(1024).decode()
            self.msg_list.insert(tkinter.END, message)

    def send_msg(self, event=None):
        """Handles sending of messages."""
        msg = self.my_msg.get()
        self.my_msg.set("")  # Clears input field.
        self.client.send(bytes(msg, "utf8"))

    def login_verify(self, event=None):
        username1 = username_verify.get()
        password1 = password_verify.get()
        username_field.delete(0, tkinter.END)
        password_field.delete(0, tkinter.END)
        h = hashlib.sha256()
        h.update(password1.encode('utf-8'))
        print(h.hexdigest())
        password1 = h.hexdigest()
        self.client.send(bytes(f"{username1}:{password1}", 'utf8'))
        srv_msg = self.client.recv(1024).decode()
        self.logged = srv_msg[:9] == "{granted}"
        if self.logged:
            self.screen.destroy()
            self.chat_window(srv_msg[9:])
        else:
            print(srv_msg)

    def login_window(self):
        global username_verify, password_verify, username_field, password_field
        self.screen = tkinter.Tk()
        self.screen.geometry("280x150")
        self.screen.title("CRYPT0CH4T Login")
        tkinter.Label(self.screen, text="Please enter details below to login").pack()
        username_verify = tkinter.StringVar()
        password_verify = tkinter.StringVar()
        tkinter.Label(self.screen, text="Username * ").pack()
        username_field = tkinter.Entry(self.screen, textvariable=username_verify)
        username_field.pack()
        tkinter.Label(self.screen, text="Password * ").pack()
        password_field = tkinter.Entry(self.screen, textvariable=password_verify, show='*')
        password_field.pack()
        password_field.bind("<Return>", self.login_verify)
        tkinter.Button(self.screen, text="Login", width=10, height=1, command=self.login_verify).pack()
        tkinter.mainloop()

    def chat_window(self, srv_msg):
        self.top = tkinter.Tk()
        self.top.title("CRYPT0CH4T")
        self.top.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.screen = tkinter.Frame(self.top)
        self.my_msg = tkinter.StringVar()  # For the messages to be sent.
        self.my_msg.set("Type your messages here.")
        scrollbar = tkinter.Scrollbar(self.screen)  # To navigate through past messages.
        # Following will contain the messages.
        self.msg_list = tkinter.Listbox(self.screen, height=30, width=55, font=12, bd=8, yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tkinter.RIGHT, fill=tkinter.Y)
        self.msg_list.pack(side=tkinter.LEFT, fill=tkinter.BOTH)
        self.msg_list.pack()
        self.screen.pack()
        entry_field = tkinter.Entry(self.top, textvariable=self.my_msg, width=55, font=10, bd=5)
        entry_field.bind("<Return>", self.send_msg)
        entry_field.pack()
        Thread(target=self.receive).start()
        if len(srv_msg) > 1:
            self.msg_list.insert(tkinter.END, srv_msg)
        tkinter.mainloop()

    def on_closing(self, event=None):
        """This function is to be called when the window is closed."""
        self.my_msg.set("{quit}")
        self.send_msg()
        print(self.client.recv(1024).decode())
        self.client.close()
        self.screen.destroy()
        self.top.destroy()
        sys.exit()

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
