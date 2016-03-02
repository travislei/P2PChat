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
import select
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
roomname = ""
msgid = 0

thread_list = []

#  P2P sockets link
forwardlink_socket = socket.socket()
backlink_list = []

mlock = threading.Lock()

_running_ = True
_connected_ = False
_KEEPALIVE_ = ""
_MYHASH_ = 0L


#
#  Set up of Basic UI
#
win = Tk()
win.title("MyP2PChat")

#  Top Frame for Message display
topframe = Frame(win, relief=RAISED, borderwidth=1)
topframe.pack(fill=BOTH, expand=True)

MsgWin = ScrolledText(topframe, height='15', padx=5, pady=5, fg="red",
              exportselection=0, insertofftime=0, state=DISABLED)
MsgWin.pack(side=LEFT, fill=BOTH, expand=True)

#  Top Middle Frame for buttons
topmidframe = Frame(win, relief=RAISED, borderwidth=1)
topmidframe.pack(fill=X, expand=True)

Butt01 = Button(topmidframe, width='8', relief=RAISED, text="User")
Butt01.pack(side=LEFT, padx=8, pady=8)

Butt02 = Button(topmidframe, width='8', relief=RAISED,
                text="List", state=DISABLED)
Butt02.pack(side=LEFT, padx=8, pady=8)

Butt03 = Button(topmidframe, width='8', relief=RAISED,
                text="Join", state=DISABLED)
Butt03.pack(side=LEFT, padx=8, pady=8)

Butt04 = Button(topmidframe, width='8', relief=RAISED,
                text="Send", state=DISABLED)
Butt04.pack(side=LEFT, padx=8, pady=8)

Butt05 = Button(topmidframe, width='8', relief=RAISED,
                text="Quit", bg="red")
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


def insert_cmd(text):
    """ Display on command window"""
    CmdWin["state"] = "normal"
    CmdWin.insert("end", text + '\n')
    CmdWin.see("end")
    CmdWin["state"] = "disabled"


def insert_msg(username, text):
    """ Display on message window"""
    MsgWin["state"] = "normal"
    MsgWin.insert("end", '[' + username + "] "+ text + '\n')
    MsgWin.see("end")
    MsgWin["state"] = "disabled"


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
    global _MYHASH_

    def __init__(self):
        self.data = []
        self.hashval = None
        self.pos = -1

    def print_info(self):
        print("[debug] Member list: ", self.data)
        print("[debug] Sorted pos.: ", self.pos + 1,
              "/", len(self.data), '\n')

    def split(self, list):
        """ Split into [User:IP:Port list]
        Source: http://stackoverflow.com/questions/1059559
        """
        _newlist = re.findall(":".join(["[^:]+"] * 3), list)
        return _newlist

    def update(self, list):
        new_hash = sdbm_hash(list)

        if new_hash == self.hashval:
            print("member list is up to date")
        else:
            print("update member list!")
            self.hashval = new_hash

            #  Split and clear
            _splited = self.split(list)
            self.data[:] = []

            #  Remove ":" and find its hash value
            for i in _splited:
                _ = i.replace(':', '')
                self.data.append((i, sdbm_hash(_)))

            #  Sort and get my position
            self.data = sorted(self.data, key=lambda x: x[1])
            self.pos = [x[1] for x in self.data].index(_MYHASH_)

            self.print_info()


#  Create a memberlist
member_list = MemberList()


def send_keepalive():
    """ Thread to send keepalive message and update memberlist """
    global mlock, _running_, _KEEPALIVE_, memberlist

    print("[debug] Start Connect thread...")

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()

    while True:
        for i in range(20):
            time.sleep(0.5)

            if _running_ is False:
                print("[debug]", thd_name, "is dying... x(")
                return

        mlock.acquire()
        print("[debug] {}: Send a keepalive message...".format(
            thd_name), end="")
        server_socket.send(_KEEPALIVE_)
        received = server_socket.recv(1024)
        mlock.release()

        if received[:2] == "M:":
            _mlist = received[2:].rstrip("::\r\n")
            member_list.update(_mlist)
        elif received[:2] == "F:":
            error_msg = ("[Join] Error: {:s}").format(
                received[2:].rstrip(":\r\n"))
            insert_cmd(error_msg)


def build_forwardlink():
    """ Function to establish a forward link """
    global member_list

    if len(member_list.data) == 1:
        insert_cmd("[Conc] Yes, you are alone! :(")
        return

    pos = (member_list.pos + 1) % len(member_list.data)

    while member_list.data[pos][1] != _MYHASH_:
        print("[debug] Find a peer: ", member_list.data[pos])

        peer_info = member_list.data[pos][0].split(':')
        insert_cmd("[Conc] Try to connect \"{}\" with address {}:{}".format(
            peer_info[0], peer_info[1], peer_info[2]
        ))

        try:
            forwardlink_socket.connect((peer_info[1], int(peer_info[2])))
            _connected_ = True
        except socket.error as e:
            print("[debug] Cannot establish forward link: ", e)
            pos = (pos + 1) %  len(member_list.data)
            continue
        #  print("[debug] New pos:", pos)



def connect_to_peer():
    """ Thread to connect to peer """
    global mlock, _running_, _connected_, member_list

    print("[debug] Start Connect thread...")

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()

    insert_cmd("[Conc] Try to connect to a peer...")
    build_forwardlink()

    while True:
        for i in range(20):
            time.sleep(0.5)

            if _running_ is False:
                print("[debug]", thd_name, "is dying... x(")
                return

        if _connected_ is False:
            insert_cmd("[Conc] Not in connected state, try again... (no peer?)")
            build_forwardlink()


def listen_to_port():
    """ Thread to listen connection(s) using select """
    global mlock, _running_, listen_socket, backlink_list, msgid

    print("[debug] Start Listen thread...")

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()

    insert_cmd("[Port] Now listening port " + str(listen_port))

    while True:
        inready, outready, excready = select.select(backlink_list, [], [], 5.0)

        if _running_ is False:
            print("[debug]", thd_name, "is dying... x(")
            return

        if not inready:
            print("[debug] {}: Idling".format(thd_name))
        else:
            for s in inready:
                if s is listen_socket:
                    peer, address = listen_socket.accept()
                    print("[debug] {}: New connection from".format(thd_name),
                          peer.getpeername())
                    backlink_list.append(peer)
                else:
                    #  data = s.recv(1024)
                    print("Receive a message")
                    # if a new message arrived, send to everybody
                    # except the sender
                    #  if data:
                        #  for w in write_list:
                            #  if w is not s:
                                #  w.send(data)
                    #  # if broken connection, remove that socket from READ
                    #  # and WRITE lists
                    #  else:
                        #  read_list.remove(s)
                        #  write_list.remove(s)
                        #  s.close()

#
#  Functions to handle user input
#
def do_User():
    global username

    _un = userentry.get()

    if _un is "":
        showwarning("Please enter your name", "Your name must not be null!")
        return

    if ":" in _un:
        showwarning("Special character!", "Cannot contain \":\"")
        return

    #  Only update usernmae if it has passed above conditions
    username = _un
    outstr = "[User] Username: " + username
    insert_cmd(outstr)

    Butt02['state'] = 'normal'
    Butt03['state'] = 'normal'
    userentry.delete(0, END)


def do_List():
    global mlock

    mlock.acquire()
    server_socket.send("L::\r\n")
    received = server_socket.recv(1024)
    mlock.release()

    if received == "G::\r\n":
        insert_cmd("[List] No active chatroom!")
    elif received[:2] == "G:":
        insert_cmd("[List] Here is/are the active chatroom(s):")

        cmd_msg = ""
        chatroom_list = received[2:].rstrip(":\r\n").split(':')
        for c in chatroom_list:
            cmd_msg += '\t\t' + c + '\n'

        #  Remove the last newline
        insert_cmd(cmd_msg.rstrip('\n'))

        #  Display which chatroom your are in
        if roomname == "":
            insert_cmd("\b\b       You are not in any chatroom.")
        else:
            insert_cmd("\b\b       You currently in \""
                         + roomname + "\".")
    elif received[:2] == "F:":
        error_msg = ("[List] Error: {:s}").format(
            received[2:].rstrip(":\r\n"))
        insert_cmd(error_msg)


def do_Join():
    global mlock, roomname, _KEEPALIVE_, _MYHASH_

    _rm = userentry.get()

    if _rm is "":
        showwarning("Please enter the room name",
                    "The room name must not be null!")
        return

    if ":" in _rm:
        showwarning("Special character!", "Cannot contain \":\"")
        return

    #  Only update roomname if it has passed above conditions
    roomname = _rm

    #  Username is now confirmed, generate hash value
    _MYHASH_ = sdbm_hash(username + userip + str(listen_port))

    #  Send message to the server
    _KEEPALIVE_ = ("J:{:s}:{:s}:{:s}:{:d}::\r\n").format(roomname, username,
                                                         userip, listen_port)
    mlock.acquire()
    server_socket.send(_KEEPALIVE_)
    received = server_socket.recv(1024)
    mlock.release()

    if received[:2] == "M:":
        #  Only delete user input if it has been successfully connected
        userentry.delete(0, END)

        #  Update the member list
        _memberlist = received[2:].rstrip("::\r\n")
        print("[debug] Join trigger...", end="")
        member_list.update(_memberlist)

        insert_cmd("[Join] You (" + username + ")" +
                   " have successfully joined the chatroom \"" +
                   roomname + "\"!\n" + "       User(s) online: " +
                   str(len(member_list.data)))

        #  Start a thread to send keepalive
        keepalive_thread = threading.Thread(name="Keepalive",
                                            target=send_keepalive)
        keepalive_thread.start()
        thread_list.append(keepalive_thread)

        #  Start a thread to listen a port
        listen_thread = threading.Thread(name="Listen",
                                            target=listen_to_port)
        listen_thread.start()
        thread_list.append(listen_thread)

        #  Start a thread to connect a peer
        connect_thread = threading.Thread(name="Connect",
                                            target=connect_to_peer)
        connect_thread.start()
        thread_list.append(connect_thread)

        #  Set buttons state
        Butt01['state'] = 'disabled'
        Butt03['state'] = 'disabled'
        Butt04['state'] = 'normal'
    elif received[:2] == "F:":
        error_msg = ("[Join] Error: {:s}").format(
            received[2:].rstrip(":\r\n"))
        insert_cmd(error_msg)


def do_Send():
    global _connected_

    if not _connected_:
        message = userentry.get()

        if message is "":
            showwarning("Please enter the room name",
                    "The room name must not be null!")
            return

        insert_msg(username, message)
        userentry.delete(0, END)


def do_Quit():
    global mlock, _running_, server_socket, listen_socket

    insert_cmd("[Quit] Shutting down...")
    _running_ = False

    for t in thread_list:
        t.join()

    server_socket.close()
    listen_socket.close()
    sys.exit(0)


# Add buttons functions
Butt01.config(command=do_User)
Butt02.config(command=do_List)
Butt03.config(command=do_Join)
Butt04.config(command=do_Send)
Butt05.config(command=do_Quit)


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

    #  Try to bind and listen to the port
    try:
        listen_socket.bind(('', listen_port))
    except socket.error as e:
        print("Socket bind error: ", e)
        sys.exit(1)

    listen_socket.listen(5)

    #  Print welcome message
    welcome_msg = ("{:s}***** Welcome to P2P Chatroom *****\n"
                   "{:s} (IP: {:s}) has connected to {:s}:{:d} and"
                   " opened a port {:d}.\n>>> Enter your name above and click"
                   " User to get started!\n{:s}").format(
                       " " * 23, hostname, userip,
                       server_addr, server_port, listen_port,
                       "-" * 80
                   )
    insert_cmd(welcome_msg)

    win.mainloop()


if __name__ == "__main__":
    main(sys.argv)
