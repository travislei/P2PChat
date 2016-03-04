#!/usr/bin/python

"""
Student name and No. : LEI WAN HONG, 3035202750
Student name and No. : HO KA KUEN,
Development platform : Mac OS X 10.11.3
Python version       : Python 2.7.10
Version              : 0.5d
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

#  Machine info
hostname = socket.gethostname()
userip = socket.gethostbyname(hostname)
username = None
roomname = ""

#  Memberlist mutex lock
mlock = threading.Lock()
thread_list = []
thread_listenforward= None

_running_ = True
_KEEPALIVE_ = ""
_MYHASH_ = 0
_SLEEPTIME_ = 5


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
    MsgWin.insert("end", "[" + username + "] " + text + '\n')
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
    global _MYHASH_, server_socket, roomname, username

    def __init__(self):
        self.data = []
        self.backlinks = []
        self.forwardlink = [None, None]
        self.msgid = 0
        self.hashval = 0
        self.pos = -1

    def peerinfo(self):
        print("[P2PInfo] Member\t:", self.data)
        print("[P2PInfo] Backlinks\t:", self.backlinks)
        print("[P2PInfo] Forward\t:", self.forwardlink)
        print("[debug] Sorted pos.: ", self.pos, "/", len(self.data) - 1, '\n')

    def send_msg(self, msg):
        self.msgid += 1

        print("[debug] Current msgid =", self.msgid)
        msg_cmd = "T:{}:{}:{}:{:d}:{}:{}::\r\n".format(
            roomname, _MYHASH_, username, int(self.msgid),
            len(msg), msg.encode("base64", "strict")
        )

        print(msg_cmd)

        if self.backlinks != []:
            for sock in self.backlinks:
                sock[0].send(msg_cmd)

        if self.forwardlink[1] != None:
                self.forwardlink[0].send(msg_cmd)


    def rcev_msg(self, msg):
        #  Split into list [roomname, hash, username, msgid, length, content]
        msg = msg[2:].rstrip(":\r\n").split(':')

        #  Decode the message
        msg[5] = msg[5].decode("base64", "strict")

        print(msg)

        if msg[0] != roomname:
            insert_cmd("[Error] Receive different chatrooms message!")
            return

        _backlink_hash = [x[1] for x in self.backlinks]

        if str(msg[1]) == str(self.forwardlink[1]):
            print("[debug] Receive message in forward link")

            print("[debug] Received msgid: {}\tCurrent msgid: {}".format(
                int(msg[3]), self.msgid
            ))
            print("[debug] Recv >= Current?", int(msg[3]) >= int(self.msgid))

            if int(msg[3]) >= int(self.msgid):
                print("[debug] msgid: ({} >= {}),"
                      " print and update msgid...".format(msg[3], self.msgid))
                insert_msg(msg[2], msg[5])
                self.msgid = int(msg[3])

                print("[debug] New msgid =", self.msgid)

        if int(msg[1]) in _backlink_hash:
            print("[debug] Receive message in backward link")

            print("[debug] Received msgid: {}\tCurrent msgid: {}".format(
                int(msg[3]), self.msgid
            ))
            print("[debug] Recv >= Current?", int(msg[3]) >= int(self.msgid))

            if int(msg[3]) >= int(self.msgid):
                print("[debug] msgid: ({} >= {}),"
                      " print and update msgid...".format(msg[3], self.msgid))
                insert_msg(msg[2], msg[5])
                self.msgid = int(msg[3])

                print("[debug] New msgid =", self.msgid)


    def split(self, list):
        """ Split into [User:IP:Port] list
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

            self.peerinfo()

    def request_update(self):
        print("[debug] Send a keepalive message...", end='')

        server_socket.send(_KEEPALIVE_)
        received = server_socket.recv(1024)

        if received[:2] == "M:":
            _list = received[2:].rstrip("::\r\n")
            self.update(_list)
        elif received[:2] == "F:":
            error_msg = ("[Join] Error: {:s}").format(
                received[2:].rstrip(":\r\n"))
            insert_cmd(error_msg)


#  Create a memberlist
member_list = MemberList()


def send_keepalive():
    """ Thread to send keepalive message and update memberlist """
    global mlock, _running_, _KEEPALIVE_, member_list

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()
    print("[{}] Start...".format(thd_name))

    while True:
        #  for i in range(_SLEEPTIME_):
        for i in range(40):
            time.sleep(0.5)

            if _running_ is False:
                print("[{}] is dying... x(".format(thd_name))
                return

        member_list.request_update()

def listen_forwadlink(sockfd):
    global mlock, member_list

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()
    print("[{}] Start...".format(thd_name))

    sockfd.settimeout(0.1)
    while True:
        try:
            data = sockfd.recv(1024)
        except socket.timeout:
            continue
        except socket.error:
            break

        if data:
            print("[{}] Recive message: {}".format(thd_name, data))

            mlock.acquire()
            member_list.rcev_msg(data)
            mlock.release()
        else:
            sockfd.close()


def build_forwardlink():
    """ Function to establish a forward link """
    global mlock, _MYHASH_, member_list, thread_listenforward
    global roomname, username, userip, listen_port

    member_list.request_update()

    #  Check if there exists any user
    if len(member_list.data) == 1:
        insert_cmd("[ERROR] You are the only user in the chatroom :(")
        return

    #  Check if forwardlink is already established
    if member_list.forwardlink[1] != None:
        print("[ERROR] Forward link already established with",
              member_list.forwardlink[0].getpeername())
        return

    #  Try position
    pos = (member_list.pos + 1) % (len(member_list.data))
    #  print("[debug] Try position:", pos, member_list.data[pos])

    peer_hash = member_list.data[pos][1]

    #  All backlinks hashes
    _backlink_hash = [x[1] for x in member_list.backlinks]
    print("[debug] Current backlinks: ", _backlink_hash)

    while (peer_hash != _MYHASH_ and
           str(peer_hash) != member_list.forwardlink[1] and
           int(peer_hash) not in _backlink_hash):

        print("[debug] Find a peer: ", pos, member_list.data[pos])

        peer_info = member_list.data[pos][0].split(':')

        _socket = socket.socket()
        _socket.settimeout(1.0)

        try:
            insert_cmd("[Conc] Connecting \"{}\" with address {}:{}".format(
                peer_info[0], peer_info[1], peer_info[2]
            ))

            _socket.connect((peer_info[1], int(peer_info[2])))
            _socket.send("P:{}:{}:{}:{}:{}::\r\n".format(
                roomname, username, userip, listen_port, member_list.msgid
            ))
            response = _socket.recv(512)
        except socket.timeout as e:
            print("[ERROR]", e)
            insert_cmd("[Conc] " + str(e) + ". Update list and" +
                       " try again...")

            #  Timeout, connection lost?
            member_list.request_update()
            pos = (pos + 1) % len(member_list.data)
            _socket.close()
            continue

        if response[:2] == "S:":
            _rcev_msgid = response[2:].rstrip(":\r\n")
            insert_cmd("[Conc] Successful! A Forward link to user \"" +
                        peer_info[0] + '\"')
            print("[debug] Received msgid: {}\tCurrent msgid: {}".format(
                _rcev_msgid, member_list.msgid
            ))

            #  Update to newest msgid
            if _rcev_msgid > member_list.msgid:
                member_list.msgid = _rcev_msgid

            #  Update forwadlink
            mlock.acquire()
            member_list.forwardlink[0] = (_socket)
            member_list.forwardlink[1] = (peer_hash)
            mlock.release()

            #  Thread to listen forwardlink message
            thread_listenforward = threading.Thread(name="Forwardlistener",
                                                    target=listen_forwadlink,
                                                    args=(_socket,))
            thread_listenforward.start()
            return
        else:
            insert_cmd("[Conc] Failed! Try next...")
            pos = (pos + 1) % len(member_list.data)
            _socket.close()

    pos = (pos + 1) % len(member_list.data)


def connect_to_forwardlink():
    """ Thread to check forwardlink establishment """
    global mlock, _running_, member_list, thread_listenforward

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()
    print("[{}] Start...".format(thd_name))

    insert_cmd("[Conc] Finding a forward link...")

    while True:
        for i in range(_SLEEPTIME_):
            time.sleep(0.5)

            if _running_ is False:
                print("[{}] is dying... x(".format(thd_name))
                return

        insert_cmd("[Conc] Checking forward link connection")
        if member_list.forwardlink[0] == None:
            insert_cmd("[Conc] No forward link is found, try again...")
            build_forwardlink()
        else:
            try:
                member_list.forwardlink[0].settimeout(1.0)
                data = member_list.forwardlink[0].recv(512)
                insert_cmd("[Conc] Forward link is already established.")
            except socket.timeout as e:
                continue

            if not data:
                #  print("[{}] Recive message: {}".format(thd_name, data))

                #  mlock.acquire()
                #  member_list.rcev_msg(data)
                #  mlock.release()
            #  else:
                insert_cmd("[Conc] Forward link is broken, build again...")

                mlock.acquire()
                member_list.forwardlink[0].close()
                member_list.forwardlink[0] = None
                member_list.forwardlink[1] = None
                mlock.release()

                thread_listenforward.join()

                build_forwardlink()


def listen_to_port():
    """ Thread to listen connection(s) using select """
    global mlock, member_list, listen_socket, _running_

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()
    print("[{}] Start...".format(thd_name))

    #  Start working
    insert_cmd("[Port] Now listening port " + str(listen_port))

    readsock_list = []
    readsock_list.append(listen_socket)

    while True:
        inready, outready, excready = select.select(readsock_list, [], [], 0.5)

        if _running_ is False:
            print("[{}] is dying... x(".format(thd_name))
            return

        if not inready:
            continue
        else:
            for s in inready:
                if s is listen_socket:
                    peer, address = listen_socket.accept()
                    print("[{}] New connection from".format(thd_name),
                          peer.getpeername())

                    readsock_list.append(peer)
                else:
                    data = s.recv(1024)

                    if data:
                        #  At this stage only if the connection has been
                        #  established, will the program enter following
                        if data[:2] == "P:":
                            member_list.request_update()

                            s.send("S:{}::\r\n".format(member_list.msgid))

                            userinfo = data[2:].rstrip(":\r\n").split(':')
                            print("[{}] Received request message {}".format(
                                thd_name, userinfo))

                            _hashpeer = sdbm_hash(userinfo[1] + userinfo[2] +
                                                  userinfo[3])

                            #  Add to backlink list for sending
                            mlock.acquire()
                            member_list.backlinks.append([s, _hashpeer])
                            mlock.release()

                            #  Inform user
                            insert_cmd("[Conc] User \"" + userinfo[1] + '\"'
                                       " (" + userinfo[2] + ":" + userinfo[3] +
                                       ") has connected to me")
                        else:
                            print("[{}] Receive a message: {}".format(
                                thd_name, data
                            ))

                            mlock.acquire()
                            member_list.rcev_msg(data)
                            mlock.release()
                    else:
                        print("[{}] Broken connection from {}"
                              " removing...".format(thd_name, s.getpeername()))

                        mlock.acquire()
                        for i in member_list.backlinks:
                            if i[0] == s:
                                insert_cmd("[Conc] Disconnect to " +
                                           str(s.getpeername()))
                                member_list.backlinks.remove(i)
                        mlock.release()

                        readsock_list.remove(s)
                        s.close()


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
            insert_cmd("\b\b       You currently in \"" + roomname + "\".")
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

    #  Username is now confirmed, generate the hash value
    _MYHASH_ = sdbm_hash(username + userip + str(listen_port))

    #  Send message to the server
    _KEEPALIVE_ = ("J:{:s}:{:s}:{:s}:{:d}::\r\n").format(roomname, username,
                                                         userip, listen_port)
    server_socket.send(_KEEPALIVE_)
    received = server_socket.recv(1024)

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
                                          target=connect_to_forwardlink)
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
    global member_list

    message = userentry.get()
    member_list.peerinfo()

    if message is "":
        showwarning("Please enter the message",
                    "The message must not be null!")
        return

    insert_msg(username, message)
    userentry.delete(0, END)

    #  Check if there is any link to send
    if len(member_list.backlinks) > 0 or member_list.forwardlink[1] != None:
        mlock.acquire()
        member_list.send_msg(message)
        mlock.release()

        print("[debug] Send message (ID: {}): {}".format(
            member_list.msgid, message))


def do_Quit():
    global mlock, _running_, server_socket, listen_socket, member_list

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
