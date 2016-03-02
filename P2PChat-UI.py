#!/usr/bin/python

"""
Student name and No. : LEI WAN HONG, 3035202750
Student name and No. : HO KA KUEN,
Development platform : Mac OS X 10.11.3
Python version       : Python 2.7.10
Version              : 0.1d
"""

from __future__ import print_function
from Tkinter import *
from ScrolledText import *
from tkMessageBox import *
import sys
import socket
import re
import time
import threading


#
#  Global variables
#
server_socket = socket.socket()
listen_socket = socket.socket()
server_addr = str(sys.argv[1])
server_port = int(sys.argv[2])
listen_port = int(sys.argv[3])

hostname = socket.gethostname()
userip = socket.gethostbyname(hostname)
username = None

thread_list = []
socket_list = []

mlock = threading.Lock()

_running_ = True
_keepalive_ = None


def sdbm_hash(instr):
    """ This is the hash function for generating a unique
    Hash ID for each peer.
    Source: http://www.cse.yorku.ca/~oz/hash.html

    Concatenate the peer's username, str(IP address),
    and str(Port) to form the input to this hash function
    """
    hash = 0L
    for c in instr:
        hash = long(ord(c)) + (hash << 6) + (hash << 16) - hash
    return hash & 0xffffffffffffffff


class MemberList(object):
    def __init__(self):
        self.values = []
        self.hashval = None

    def print_value(self):
        print("[debug] Member list: ", self.values, '\n')

    def split(self, list):
        """ Split into User:IP:Port list
        Source: http://stackoverflow.com/questions/1059559
        """
        _newlist = re.findall(":".join(["[^:]+"] * 3), list)
        return _newlist

    def update(self, list):
        new_hash = sdbm_hash(list)

        if new_hash == self.hashval:
            print("[debug] Member list is up to date")
            self.print_value()
        else:
            print("[debug] Update member list...")
            self.hashval = new_hash

            #  Split and remove ":"
            _splited = self.split(list)
            self.values[:] = []
            for i in _splited:
                _ = i.replace(':', '')
                self.values.append((_, sdbm_hash(_)))

            self.values.sort(key=lambda x: x[1])
            self.print_value()


#  Create a memberlist
member_list = MemberList()


def keepalive():
    """ Thread to send keepalive message and update memberlist """
    global _running_, _keepalive_, memberlist

    thd_name = threading.current_thread().getName()

    while True:
        for i in range(5):
            time.sleep(0.5)

            if _running_ is False:
                print("[debug]", thd_name, "is dying... x(")
                return

        mlock.acquire()
        print("[debug] Send a keepalive message")
        server_socket.send(_keepalive_)
        received = server_socket.recv(1024)
        mlock.release()

        if received[:2] == "M:":
            _mlist = received[2:].rstrip("::\r\n")
            member_list.update(_mlist)
        elif received[:2] == "F:":
            error_msg = ("[Join] Error: {:s}").format(
                received[2:].rstrip(":\r\n"))
            display_text(CmdWin, error_msg)


def display_text(window, text):
    """ Display string on specified window """
    window["state"] = "normal"
    window.insert("end", text + '\n')
    window.see("end")
    window["state"] = "disabled"


#
#  Functions to handle user input
#
def do_User():
    global username

    username = userentry.get()

    if username is "":
        showwarning("Please enter your name", "Your name must not be null!")
        return

    if ":" in username:
        showwarning("Special character!", "Cannot contain \":\"")
        return

    outstr = "[User] Username: " + username
    display_text(CmdWin, outstr)

    Butt02['state'] = 'normal'
    Butt03['state'] = 'normal'
    userentry.delete(0, END)


def do_List():
    mlock.acquire()
    server_socket.send("L::\r\n")
    received = server_socket.recv(1024)
    mlock.release()

    if received == "G::\r\n":
        display_text(CmdWin, "[List] No active chatroom!")
    elif received[:2] == "G:":
        display_text(CmdWin, "[List] Here are the active chatroom(s):")

        cmd_msg = ""
        chatroom_list = received[2:].rstrip(":\r\n").split(':')
        for c in chatroom_list:
            cmd_msg += '\t' + c + '\n'

        display_text(CmdWin, cmd_msg + "No room")
    elif received[:2] == "F:":
        error_msg = ("[List] Error: {:s}").format(
            received[2:].rstrip(":\r\n"))
        display_text(CmdWin, error_msg)


def do_Join():
    global _keepalive_

    roomname = userentry.get()

    if roomname is "":
        showwarning("Please enter the room name",
                    "The room name must not be null!")
        return

    if ":" in roomname:
        showwarning("Special character!", "Cannot contain \":\"")
        return

    #  Send message to the server
    mlock.acquire()
    _keepalive_ = ("J:{:s}:{:s}:{:s}:{:d}::\r\n").format(roomname, username,
                                                         userip, listen_port)
    server_socket.send(_keepalive_)
    received = server_socket.recv(1024)
    mlock.release()

    if received[:2] == "M:":
        #  Only delete user input if it has been successfully connected
        userentry.delete(0, END)
        _memberlist = received[2:].rstrip("::\r\n")
        member_list.update(_memberlist)

        display_text(CmdWin,
                     "[Join] You (" + username + ")" +
                     " have successfully joined the chatroom \"" +
                     roomname + "\"!")

        #  Start a thread to send keepalive
        print("[debug] Start Keepalive thread...")
        keepalive_thread = threading.Thread(name="Keepalive",
                                            target=keepalive)
        keepalive_thread.start()
        thread_list.append(keepalive_thread)

        #  Set buttons state
        Butt01['state'] = 'disabled'
        Butt03['state'] = 'disabled'
        Butt04['state'] = 'normal'
    elif received[:2] == "F:":
        error_msg = ("[Join] Error: {:s}").format(
            received[2:].rstrip(":\r\n"))
        display_text(CmdWin, error_msg)


def do_Send():
    CmdWin.insert(1.0, "\nPress Send")


def do_Quit():
    global _running_, server_socket, listen_socket

    display_text(CmdWin, "[Quit] Shutting down...")
    _running_ = False

    for t in thread_list:
        t.join()

    server_socket.close()
    listen_socket.close()
    sys.exit(0)

#
#  Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#  Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)

MsgWin = Text(topframe, height='15', padx=5, pady=5, fg="red",
              exportselection=0, insertofftime=0)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)

topscroll = Scrollbar(topframe)
topscroll.pack(side=RIGHT, fill=Y, expand=True)

topscroll.config(command=MsgWin.yview)
MsgWin.config(yscrollcommand=topscroll.set)

#  Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)

Butt01 = Button(topmidframe, width='8', relief=RAISED,
                text="User", command=do_User)
Butt01.pack(side=LEFT, padx=8, pady=8)

Butt02 = Button(topmidframe, width='8', relief=RAISED,
                text="List", command=do_List, state=DISABLED)
Butt02.pack(side=LEFT, padx=8, pady=8)

Butt03 = Button(topmidframe, width='8', relief=RAISED,
                text="Join", command=do_Join, state=DISABLED)
Butt03.pack(side=LEFT, padx=8, pady=8)

Butt04 = Button(topmidframe, width='8', relief=RAISED,
                text="Send", command=do_Send, state=DISABLED)
Butt04.pack(side=LEFT, padx=8, pady=8)

Butt05 = Button(topmidframe, width='8', relief=RAISED,
                text="Quit", command=do_Quit, bg="red")
Butt05.pack(side=LEFT, padx=8, pady=8)

#  Lower Middle Frame for User input
lowmidframe = Frame(win, relief=RAISED, borderwidth=1)
lowmidframe.pack(fill=X, expand=True)

userentry = Entry(lowmidframe, fg="blue")
userentry.pack(fill=X, padx=4, pady=4, expand=True)

#  Bottom Frame for displaying action info
bottframe = Frame(win, relief=RAISED, borderwidth=1)
bottframe.pack(fill=BOTH, expand=True)

CmdWin = ScrolledText(bottframe, height='15', padx=5, pady=5, bg="#E9E9E9",
                      exportselection=0, insertofftime=0, state=DISABLED)
CmdWin.pack(side=LEFT, fill=BOTH, expand=True)


def main(argv):
    global server_socket, listen_socket

    if len(sys.argv) != 4:
        print("P2PChat.py <server address> <server port no.> <my port no.>")
        sys.exit(2)

    #  Connect to the server
    print(hostname, "is connecting to", server_addr, ":", server_port)

    try:
        server_socket.connect((server_addr, server_port))
    except socket.error as e:
        print("Cannot connect to the server: ", e)
        sys.exit(1)

    #  Setup listening port for peers
    try:
        listen_socket.bind(('', listen_port))
    except socket.error as e:
        print("Socket bind error: ", e)
        sys.exit(1)

    listen_socket.listen(5)

    #  Print welcome message
    welcome_msg = ("{:s}***** Welcome to P2P Chatroom *****\n"
                   "{:s} (IP: {:s}) has connected to {:s}:{:d} and"
                   " listened a port {:d}.\n>>> Enter your name above and click"
                   " User to get started!\n{:s}").format(
                       " " * 23, hostname, userip,
                       server_addr, server_port, listen_port,
                       "-" * 80
                   )
    display_text(CmdWin, welcome_msg)

    win.mainloop()


if __name__ == "__main__":
    main(sys.argv)
