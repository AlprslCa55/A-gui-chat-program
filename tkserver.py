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
root.title("Server")
right_frame = tk.Frame(master=root)
right_frame.pack(side="right", fill="y", expand=True)
right_frame_label = tk.Label(master=right_frame, text="Client Connections", width=78, bd=1, relief="sunken")
right_frame_label.pack(side="top", fill="x")
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


button_frame = tk.Frame(master=root)
button_frame.pack()


def buttons(*args, master):
    for i in args:
        b = tk.Button(master=master, text=i)
        b.pack(side="left")
        yield b


b1, b2, b3, b4 = buttons("Connect", "Clear", "File Transfer", "Exit", master=button_frame)


def do_nothing():
    pass


class Server:
    clients1 = []
    clients2 = []
    client_names = []
    client_frames = []

    def __init__(self):
        self.s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def __connect__(self, port):
        try:
            self.s1.bind(("0.0.0.0", port))
            self.s1.listen(10)
            self.s2.bind(("0.0.0.0", port + 1))
            self.s2.listen(10)
            tag_controller(message="Connected.")

            def warning():
                tag_controller(message="You are already connected.")

            b1.configure(command=warning)
            self.thread_control()
        except PermissionError:
            tag_controller(message="Permission denied.")
        except OverflowError:
            tag_controller(message="Port must be 0-65535.")
        except OSError:
            tag_controller(message="Address already in use.")

    def __accept__(self):
        conn1, addr1 = self.s1.accept()
        conn2, addr2 = self.s2.accept()
        data = conn1.recv(1024).decode("utf-8")
        self.client_names.append(data)
        self.clients1.append((conn1, data))
        self.clients2.append((conn2, data))
        tag_controller(message="{} connected.".format(data), nickname=data, color="red")
        client_frame = tk.Frame(master=right_frame)
        client_frame.pack()
        self.client_frames.append(client_frame)
        client_label = tk.Label(master=client_frame, text=data, width=20, bd=1, relief="sunken")
        client_label.pack(side="left")
        entry = tk.Entry(master=client_frame, width=50)
        entry.pack(side="left")
        b5, = buttons("Send", master=client_frame)

        def send():

            def __send__():
                respond = ".:!:.Server: {}.:!:.".format(str(entry.get()))
                entry.delete("0", "end")
                try:
                    conn1.sendall(bytes(respond.encode("utf-8")))
                    tag_controller(message="{}".format(respond.replace(".:!:.", "")), nickname="Server", color="blue")
                except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                    pass

            thread_send = threading.Thread(target=__send__)
            thread_send.start()

        b5.configure(command=send)

        def receive_message():
            while True:
                try:
                    data1 = conn1.recv(1024)
                    regex = b"".join(re.findall(b"\.:!:\.[^{}]+: [^{}]+\.:!:\.", data1))
                    if regex:
                        tag_controller(message="{}".format(regex.replace(b".:!:.", b"").decode("utf-8")),
                                       nickname=data, color="red")
                except (ConnectionResetError, OSError):
                    pass

        thread_receive_message = threading.Thread(target=receive_message)
        thread_receive_message.start()

        def receive_file():
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
                    data2 = conn2.recv(1024 ** 2)
                    regex = b"".join(re.findall(b"\.:!:\.[^{}]+&[^{}]+\.:!:\.", data2))
                    if regex:
                        filename, filesize = regex.replace(b".:!:.", b"").decode("utf-8").split("&")
                        __filename__ += filename
                        __filesize__ += int(filesize)
                        tag_controller(message="{} wants to send you {}.".format(data, filename), nickname=data,
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

        thread_receive_file = threading.Thread(target=receive_file)
        thread_receive_file.start()

    def file_transfer(self):
        b3.configure(command=do_nothing)
        __frame__ = tk.Frame(master=root)
        __frame__.pack()

        def client_names(name):

            def __client__names__():

                def __file_transfer__():
                    try:
                        name_index = self.client_names.index(name)
                        file = filedialog.askopenfilename(filetypes=[("All Files", ".*")])
                        try:
                            filename = os.path.basename(file)
                            file = open(file, "rb")
                            data = file.read()

                            def send_file_info():
                                try:
                                    self.clients2[name_index][0].sendall(
                                        bytes(".:!:.{}&{}.:!:.".format(filename, str(len(data))).encode("utf-8")))
                                except (ConnectionResetError, BrokenPipeError, IndexError):
                                    pass

                            thread_send_file_info = threading.Thread(target=send_file_info)
                            thread_send_file_info.start()
                            time.sleep(1)
                            while data:
                                try:
                                    self.clients2[name_index][0].sendall(data)
                                    data = file.read()
                                except (ConnectionResetError, BrokenPipeError, IndexError):
                                    __frame__.destroy()
                            file.close()
                            __frame__.destroy()
                        except (TypeError, FileNotFoundError):
                            __frame__.destroy()
                    except ValueError:
                        __frame__.destroy()

                thread_file_transfer = threading.Thread(target=__file_transfer__)
                thread_file_transfer.start()

            return __client__names__

        for i, j in enumerate(self.client_names):
            b6, = buttons(j, master=__frame__)
            b6.configure(command=client_names(self.client_names[i]))
        b3.configure(command=self.file_transfer)

    def __manage_variables__(self):
        for i, j in enumerate(self.clients1):
            try:
                j[0].send(bytes(".:!:.test.:!:.".encode("utf-8")))
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                tag_controller(message="{} is disconnected.".format(j[1]), nickname=j[1], color="red")
                self.client_frames[i].destroy()
                self.client_frames.pop(i)
                self.client_names.pop(i)
                j[0].close()
                self.clients2[i][0].close()
                self.clients2.pop(i)
                self.clients1.pop(i)

    def thread_control(self):
        while True:
            thread_accept = threading.Thread(target=self.__accept__)
            thread_accept.daemon = True
            thread_accept.start()
            thread_accept.join(1)
            thread_manage = threading.Thread(target=self.__manage_variables__)
            thread_manage.daemon = True
            thread_manage.start()
            thread_manage.join(1)


server = Server()


def connect():
    b1.configure(command=do_nothing)
    connect_frame = tk.Frame(master=root)
    connect_frame.pack(side="bottom")
    port_label = tk.Label(master=connect_frame, text="PORT: ")
    port_label.grid(row=0, column=0)
    port_entry = tk.Entry(master=connect_frame, width=10)
    port_entry.grid(row=0, column=1)
    accept_port = tk.Button(master=connect_frame, text="Accept")
    accept_port.grid(row=0, column=2, columnspan=2)

    def accept():
        b1.configure(command=connect)
        try:
            thread_connect = threading.Thread(target=server.__connect__, args=(int(port_entry.get()),))
            thread_connect.start()
        except ValueError:
            tag_controller(message="Port value is invalid.")
        connect_frame.destroy()

    accept_port.configure(command=accept)


def clear():
    global count
    text.configure(state="normal")
    text.delete("1.0", "end")
    text.configure(state="disabled")
    count = 1


def destroy():
    server.s1.close()
    server.s2.close()
    if os.name == "posix":
        import signal
        os.kill(os.getpid(), signal.SIGKILL)
    elif os.name == "nt":
        os.system("TASKKILL /F /PID {}".format(os.getpid()))


b1.configure(command=connect)
b2.configure(command=clear)
b3.configure(command=server.file_transfer)
b4.configure(command=destroy)

if __name__ == "__main__":
    if os.name == "nt":

        def source_path(relative_path):
            import sys
            base_path = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
            return os.path.join(base_path, relative_path)

        root.iconbitmap(source_path("tkicon.ico"))
    main_thread = threading.Thread(target=root.mainloop)
    main_thread.run()
