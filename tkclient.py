#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import time
import socket
import threading
from datetime import datetime
try:
    import Tkinter as tk
except ImportError:
    import tkinter as tk
try:
    import ttk
except ImportError:
    import tkinter.ttk as ttk
try:
    import Tkinter.tkFileDialog as filedialog
except ImportError:
    import tkinter.filedialog as filedialog

root = tk.Tk()
root.title("Client")
text = tk.Text(master=root, state="disabled")
text.pack(expand=True, fill="both")
count = 1
tag_name = ""


def tag(now, name, nickname="", color="black"):
    len1 = len(now) + 2
    len2 = len(nickname) + 1
    text.tag_add(name + "0", "{}.0".format(count), "{}.1".format(count))
    text.tag_configure(name + "0", foreground="green")
    text.tag_add(name + "1", "{}.1".format(count), "{}.{}".format(count, len1))
    text.tag_configure(name + "1", foreground="purple")
    text.tag_add(name + "2", "{}.{}".format(count, len1), "{}.{}".format(count, len1 + 2))
    text.tag_configure(name + "2", foreground="green")
    text.tag_add(name + "3", "{}.{}".format(count, len1 + 2), "{}.{}".format(count, len1 + len2 + 2))
    text.tag_configure(name + "3", foreground=color)


def tag_controller(message, nickname="", color="black"):
    global count, tag_name
    text.configure(state="normal")
    text.insert("insert", "| {} | {}\n".format(str(datetime.now())[:-7], message))
    text.configure(state="disabled")
    tag(now=str(datetime.now())[:-7], name=tag_name, nickname=nickname, color=color)
    count += 1
    tag_name += str(count)


entry = tk.Entry(master=root)
entry.pack(expand=True, fill="x")
frame = tk.Frame(master=root)
frame.pack()


def buttons(*args, master, side):
    for i in args:
        b = tk.Button(master=master, text=i)
        b.pack(side=side)
        yield b


b1, b2, b3, b4, b5, b6 = buttons("Connect", "Create A Nickname", "Send", "Clear", "File Transfer", "Exit",
                                 master=frame, side="left")
__nickname__ = ""


def do_nothing():
    pass


class Client:

    def __init__(self):
        self.s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def __connect__(self, host, port):
        try:
            self.s1.connect((host, port))
            self.s2.connect((host, port + 1))
            tag_controller(message="Connected.")
            self.s1.sendall(bytes("{}".format(__nickname__).encode("utf-8")))

            def warning():
                tag_controller(message="You are already connected.")

            b1.configure(command=warning)
            thread_receive_message = threading.Thread(target=self.receive_message)
            thread_receive_message.start()
            thread_receive_file = threading.Thread(target=self.receive_file)
            thread_receive_file.start()
        except ConnectionRefusedError:
            tag_controller(message="The server is not online.")
        except socket.gaierror:
            tag_controller(message="Name or service is unknown.")
        except TimeoutError:
            tag_controller(message="Timed out.")
        except OverflowError:
            tag_controller(message="Port must be 0-65535.")

    def receive_message(self):
        while True:
            try:
                data1 = self.s1.recv(1024)
                if ".:!:.test.:!:.".encode("utf-8") in data1:
                    data1 = data1.replace(b".:!:.test.:!:.", b"")
                regex = b"".join(re.findall(b"\.:!:\.[^{}]+: [^{}]+\.:!:\.", data1))
                if regex:
                    tag_controller(message="{}".format(regex.replace(b".:!:.", b"").decode("utf-8")),
                                   nickname="Server", color="red")
            except (ConnectionResetError, OSError):
                pass

    def receive_file(self):
        global count
        __filename__ = ""
        __filesize__ = 0
        __received__ = 0
        __now__ = 0
        pframe = tk.Frame(master=root)
        pbar = ttk.Progressbar(master=pframe, orient="horizontal", length=200, mode="determinate")
        pstring = tk.StringVar()
        plabel = tk.Label(master=pframe, textvariable=pstring)
        while True:
            try:
                data2 = self.s2.recv(1024 ** 2)
                regex = b"".join(re.findall(b"\.:!:\.[^{}]+&[^{}]+\.:!:\.", data2))
                if regex:
                    filename, filesize = regex.replace(b".:!:.", b"").decode("utf-8").split("&")
                    __filename__ += filename
                    __filesize__ += int(filesize)
                    tag_controller(message="Server wants to send you {}.".format(filename), nickname="Server",
                                   color="red")
                    tag_controller(message="Size: {} byte.".format(filesize), nickname="Size", color="brown")
                    if pframe is None and pbar is None and plabel is None:
                        pframe = tk.Frame(master=root)
                        pframe.pack()
                        pbar = ttk.Progressbar(master=pframe, orient="horizontal", length=200, mode="determinate")
                        pbar.pack(side="left")
                        plabel = tk.Label(master=pframe, textvariable=pstring)
                        plabel.pack(side="left")
                    else:
                        pframe.pack()
                        pbar.pack(side="left")
                        plabel.pack(side="left")
                    __now__ = time.time()
                    time.sleep(1)
                else:
                    if __filename__ == "":
                        pass
                    else:
                        with open("new_{}".format(__filename__), "ab") as f:
                            f.write(data2)
                            __received__ += len(data2)
                            if __filesize__ == __received__:
                                tag_controller(message="{} is received.".format(__filename__),
                                               nickname=__filename__, color="orange")
                                __filename__ = ""
                                __filesize__ = 0
                                __received__ = 0
                                pframe.destroy()
                                pframe = None
                                pbar = None
                                plabel = None
                            else:
                                pbar["value"] = __received__
                                pbar["maximum"] = __filesize__
                                pstring.set("{} %,  {} b/s, {} seconds remaining.".format(
                                    int(100 * __received__ / __filesize__),
                                    int(__received__ / (time.time() - __now__)),
                                    int(__filesize__ / (__received__ / (time.time() - __now__))) - int(
                                        time.time() - __now__)))
            except (ConnectionResetError, OSError):
                if pframe is not None:
                    pframe.destroy()
                    pframe = None
                    pbar = None
                    plabel = None

    def send(self):

        def __send__():
            respond = ".:!:.{}: {}.:!:.".format(__nickname__, str(entry.get()))
            entry.delete("0", "end")
            try:
                self.s1.sendall(bytes(respond.encode("utf-8")))
                tag_controller(message="{}".format(respond.replace(".:!:.", "")), nickname=__nickname__, color="blue")
            except (BrokenPipeError, ConnectionResetError, OSError):
                tag_controller(message="Not connected to the server.")
                self.s1.close()
                self.s2.close()
                self.s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                b1.configure(command=connect)

        thread_send = threading.Thread(target=__send__)
        thread_send.start()

    def file_transfer(self):

        def __file_transfer__():
            file = filedialog.askopenfilename(filetypes=[("All Files", ".*")])
            try:
                filename = os.path.basename(file)
                file = open(file, "rb")
                data = file.read()

                def send_file_info():
                    try:
                        self.s2.sendall(bytes(".:!:.{}&{}.:!:.".format(filename, str(len(data))).encode("utf-8")))
                    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                        pass

                thread_send_file_info = threading.Thread(target=send_file_info)
                thread_send_file_info.start()
                time.sleep(1)
                while data:
                    try:
                        self.s2.sendall(data)
                        data = file.read()
                    except (ConnectionResetError, BrokenPipeError, IndexError, OSError):
                        pass
                file.close()
            except (TypeError, FileNotFoundError):
                pass

        t2 = threading.Thread(target=__file_transfer__)
        t2.start()


client = Client()


def connect():
    global __nickname__
    if __nickname__ != "":
        b1.configure(command=do_nothing)
        connect_frame = tk.Frame(master=root)
        connect_frame.pack(side="bottom")

        def widgets():
            for i, j in enumerate(("HOST:", "PORT:")):
                __label__ = tk.Label(master=connect_frame, text=j)
                __label__.grid(row=i, column=0)
                __entry__ = tk.Entry(master=connect_frame, width=15)
                __entry__.grid(row=i, column=1)
                yield __label__
                yield __entry__

        l1, e1, l2, e2 = widgets()
        accept_button = tk.Button(master=connect_frame, text="Accept")
        accept_button.grid(row=0, column=3, rowspan=2)

        def accept():
            try:
                if e1.get() == "":
                    thread_connect = threading.Thread(target=client.__connect__, args=("127.0.0.1", int(e2.get())))
                    thread_connect.start()
                else:
                    thread_connect = threading.Thread(target=client.__connect__, args=(e1.get(), int(e2.get())))
                    thread_connect.start()
            except ValueError:
                tag_controller(message="Port value is invalid.")
            connect_frame.destroy()

        accept_button.configure(command=accept)
    else:
        tag_controller(message="You must create a nickname.")


def create_nickname():
    b2.configure(command=do_nothing)
    __frame__ = tk.Frame(master=root)
    __frame__.pack()
    __entry__ = tk.Entry(master=__frame__)
    __entry__.pack(side="top")
    b7, = buttons("Accept Your Nickname", master=__frame__, side="top")

    def __create_nickname__():
        global __nickname__
        if __entry__.get() == "":
            tag_controller(message="You must write a nickname.")
        else:
            __nickname__ = __entry__.get()
            __frame__.destroy()
            tag_controller(message="Nickname has changed to: '{}'.".format(__nickname__))
            root.title(__nickname__)
            b2.destroy()

    b7.configure(command=__create_nickname__)


def clear():
    global count
    text.configure(state="normal")
    text.delete("1.0", "end")
    text.configure(state="disabled")
    count = 1


def destroy():
    client.s1.close()
    client.s2.close()
    if os.name == "posix":
        import signal
        os.kill(os.getpid(), signal.SIGKILL)
    elif os.name == "nt":
        os.system("TASKKILL /F /PID {}".format(os.getpid()))


b1.configure(command=connect)
b2.configure(command=create_nickname)
b3.configure(command=client.send)
b4.configure(command=clear)
b5.configure(command=client.file_transfer)
b6.configure(command=destroy)

if __name__ == "__main__":
    if os.name == "nt":
        def source_path(relative_path):
            import sys
            base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
            return os.path.join(base_path, relative_path)


        root.iconbitmap(source_path("tkicon.ico"))
    main_thread = threading.Thread(target=root.mainloop)
    main_thread.run()
