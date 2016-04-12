#!/usr/bin/python

"""
Student name and No. : LEI WAN HONG, 3035202750
Student name and No. : HO KA KUEN, 3035074878
Development platform : Mac OS X 10.11.3
Python version       : Python 2.7.10
Version              : 1.1rc
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
mlock = threading.Lock()    # Mutex lock for Memberlist object
thread_list = []
thread_listenforward = None

_run_fdlistener_ = False    # Flag for "listen_forwardlink" thread
_running_ = True            # Normal thread running flag
_KEEPALIVE_ = ""            # Unique keepalive message, defined in do_Join
_MYHASH_ = 0                # Unique hash value
_SLEEPTIME_ = 5             # Thread sleep


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


class PeerList(object):
    global _MYHASH_, server_socket, roomname, username, Butt04

    def __init__(self):
        self.data = []                      # Peer list, easier for sorting
        self.msgid = {}                     # Peer msgid, O(1) for retrieve!
        self.hashval = 0                    # Hashval of _Peer List_
        self.backlinks = []                 # Backward link list
        self.forwardlink = [None, None]     # Forward link [sockfd, hashval]
        self.my_msgid = 0                   # Current message id
        self.pos = -1                       # Search peer position

    def print_peerinfo(self):
        print("[P2PInfo] Peer\t:", self.data)
        print("[P2PInfo] Peer msgid\t:", self.msgid)
        print("[P2PInfo] Backward\t:", self.backlinks)
        print("[P2PInfo] Forward\t:", self.forwardlink)
        print("[P2PInfo] Sorted pos.: ",
              self.pos, "/", len(self.data) - 1, '\n')

    def is_connected(self):
        if len(self.backlinks) > 0 or self.forwardlink[1] != None:
            if Butt04['state'] == 'disabled':
                Butt04['state'] = 'normal'
            return True
        else:
            Butt04['state'] = 'disabled'
            return False

    def print_state(self):
        if self.is_connected():
            insert_cmd("[Conc] You are connected to peer(s)")
        else:
            insert_cmd("[ERRO] Your are disconnected!")

    def get_backlinkhash(self):
        """ Generate the backlink hashval """
        if self.backlinks == []:
            return []
        else:
            return [x[1] for x in self.backlinks]

    def send_msg(self, msg):
        #  DEBUG
        self.print_state()

        self.my_msgid += 1

        print("[send_msg] Current msgid =", self.my_msgid)
        msg_cmd = "T:{}:{}:{}:{}:{}:{}::\r\n".format(
            roomname, _MYHASH_, username, self.my_msgid, len(msg), msg)

        print("[send_msg]", msg_cmd)

        if self.backlinks != []:
            for sockfd in self.backlinks:
                print("[send_msg] Send to backlink:", sockfd[1])
                sockfd[0].sendall(msg_cmd)

        if self.forwardlink[1] != None:
            print("[send_msg] Send to forwardlink", self.forwardlink[1])
            self.forwardlink[0].sendall(msg_cmd)

    def rely_msg(self, sockfd, msg):
        print("[rely_msg] Rely message to ", sockfd.getpeername())

        try:
            sockfd.sendall(msg)
        except socket.error as e:
            print("[rely_msg]", e)

    def recv_msg(self, msg):
        #  Split into list [roomname, hash, username, msgid, length, content]
        #  and decode the message
        orig_msg = msg
        msg = msg[2: len(msg) - 4].split(':', 5)
        msg[1] = str(msg[1])

        if msg[0] != roomname:
            insert_cmd("[recv_msg] Receive different chatrooms message!")
            return

        #  Not in our msgid? Create it!
        if msg[1] not in self.msgid:
            print("[recv_msg] Never receive any msg from this peer,"
                  " update peer's msgid")
            self.msgid[msg[1]] = int(msg[3])

        #  In-order arrival
        elif int(msg[3]) != self.msgid[msg[1]] + 1:
            print("[recv_msg] Not expcected msgid", self.msgid[msg[1]] + 1)
            return
        elif int(msg[3]) == self.msgid[msg[1]] + 1:
            self.msgid[msg[1]] += 1
            print("[recv_msg] Update msgid to", self.msgid[msg[1]])

        #  Print it!
        insert_msg(msg[2], msg[5])
        #  DEBUG: Print the message
        print("[recv_msg]", msg)
        print("[recv_msg]", "Recv id", msg[3],
              "\tCurrent peer id:", self.msgid[msg[1]])

        #  Check it source and rely to peers,
        #  if from forward link, rely to all backlinks, if any
        if str(msg[1]) == str(self.forwardlink[1]):
            if self.backlinks != []:
                for s in self.backlinks:
                    self.rely_msg(s[0], orig_msg)

        #  if from one of the backward link
        else:
            print("[recv_msg] From backward link")

            #  Rely to forward link, if any
            if self.forwardlink[1] != None:
                self.rely_msg(self.forwardlink[0], orig_msg)

            print("[recv_msg]", self.backlinks)
            #  Rely to all backward links exculding the sender
            for s in self.backlinks:
                print("[recv_msg] Checkout ", s[1], str(s[1]) == str(msg[1]))
                if str(s[1]) != str(msg[1]):
                    print("[recv_msg] Rely to:", s[1])
                    self.rely_msg(s[0], orig_msg)

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
            peerhash_list = []

            #  Remove ":" and find its hash value
            for i in _splited:
                hashval = sdbm_hash(i.replace(':', ''))
                self.data.append((i, hashval))
                peerhash_list.append(str(hashval))

            #  Remove the msgid if it is outdated
            #  i.e. not in updated member list
            for key in self.msgid.keys():
                if str(key) not in peerhash_list:
                    del self.msgid[str(key)]

            #  Sort and get my position
            self.data = sorted(self.data, key=lambda x: x[1])
            self.pos = [x[1] for x in self.data].index(_MYHASH_)

            self.print_peerinfo()

    def request_update(self):
        """ It differs from above as it sends a keepalive message """
        print("[debug] Send a keepalive message...", end='')

        server_socket.send(_KEEPALIVE_)
        received = server_socket.recv(500)

        if received[:2] == "M:":
            _list = received[2:].rstrip("::\r\n")
            self.update(_list)
        elif received[:2] == "F:":
            error_msg = ("[Join] Error: {:s}").format(
                received[2:].rstrip(":\r\n"))
            insert_cmd(error_msg)

    def try_peerpos(self):
        """ Next peer position for P2P connection """
        self.request_update()

        #  Only 1 user then quit
        if len(self.data) == 1:
            return -1

        #  Let the position be peerpos and get its hashval
        peerpos = (self.pos + 1) % len(self.data)
        peer_hash = self.data[peerpos][1]

        #  Generate backlink hashval
        backlink_hash = self.get_backlinkhash()

        #  Generate current user hashval, except ourselves
        data_hash = []
        for d in self.data:
            if d[1] != _MYHASH_:
                data_hash.append(d[1])

        #  Check if all user has connected to me
        if set(data_hash) == set(backlink_hash):
            return -2

        #  Try next peer if its hash values is
        #      1. equal to my hashval <=> equal to myself
        #      2. equal to forwardlink
        #      3. is in the backlink
        while (peer_hash == _MYHASH_ or
               peer_hash == self.forwardlink[1] or
               peer_hash in backlink_hash):

            peer_info = self.data[peerpos][0].split(':')

            #  DEBUG: Info printing
            print("[try_peerpos] Try pos.:", peerpos)
            print("[try_peerpos] Peerinfo:", peer_info)
            print("[try_peerpos] Equal to forwardlink[1]?",
                  peer_hash == self.forwardlink[1])
            print("[try_peerpos] In backlink?", peer_hash in backlink_hash)
            print("[try_peerpos] Peerhash:", peer_hash)
            print("[try_peerpos] backlink_hash:", backlink_hash, '\n')

            #  Need to update and retry
            self.request_update()

            peerpos = (peerpos + 1) % len(self.data)
            backlink_hash = self.get_backlinkhash()
            peer_hash = self.data[peerpos][1]

        return peerpos


#  Create a peerlist
peerlist = PeerList()


def send_keepalive():
    """ Thread to send keepalive message and update memberlist """
    global mlock, _running_, _KEEPALIVE_, peerlist

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()
    print("[{}] Start...".format(thd_name))

    while True:
        for i in range(40):
            time.sleep(0.5)

            if _running_ is False:
                print("[{}] is dying... x(".format(thd_name))
                return

        insert_cmd("[Conc] Send a keepalive message")
        peerlist.request_update()


def listen_forwardlink(sockfd, hashval):
    """ Thread to receive message from the connected forward link """
    global mlock, peerlist, _run_fdlistener_

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()
    print("[{}] Start...".format(thd_name))

    #  Set timeout for the socket
    sockfd.settimeout(1)

    while _run_fdlistener_:
        try:
            msg = sockfd.recv(500)
        except socket.timeout:
            continue

        if msg:
            print("[{}] Recive message: {}".format(thd_name, msg))
            peerlist.recv_msg(msg)
        elif not msg:
            insert_cmd("[Conc] Forward link is broken, build again...")

            #  Remove socket from forwardlink and msgid
            mlock.acquire()
            peerlist.forwardlink[0] = None
            peerlist.forwardlink[1] = None

            if hashval in peerlist.msgid:
                del peerlist.msgid[hashval]
            mlock.release()

            build_forwardlink()
            break

    sockfd.close()
    print("[{}] is dying... x(".format(thd_name))
    return


def build_forwardlink():
    """ Function to establish a forward link """
    global mlock, _MYHASH_, peerlist, thread_listenforward, _run_fdlistener_
    global roomname, username, userip, listen_port

    #  Get the peer position
    pos = peerlist.try_peerpos()

    #  Check if there exists any user
    if pos == -1:
        insert_cmd("[ERRO] You are the only user in the chatroom :(")
        return
    elif pos == -2:
        insert_cmd("[ERRO] All users have connected to me," +
                   " wait for another user")
        return

    #  Get the necessary info now
    peer_info = peerlist.data[pos][0].split(':')
    peer_hash = peerlist.data[pos][1]
    print("[build_forwardlink] Try pos.:", pos)
    print("[build_forwardlink] Peerinfo:", peer_info)

    #  Build a socket and try to connect it!
    sockfd = socket.socket()

    try:
        insert_cmd("[Conc] Connecting \"{}\" with address {}:{}".format(
            peer_info[0], peer_info[1], peer_info[2]
        ))

        sockfd.connect((peer_info[1], int(peer_info[2])))
        sockfd.send("P:{}:{}:{}:{}:{}::\r\n".format(
            roomname, username, userip, listen_port, peerlist.my_msgid
        ))
        response = sockfd.recv(500)
    except socket.error as e:
        print("[build_forwardlink]", e)
        insert_cmd("[Conc] " + str(e) + ". Update list and" +
                   " try again...")

        #  Try again?
        peerlist.request_update()
        return

    #  Receive success message from peer
    if response[:2] == "S:":
        recv_msgid = response[2:].rstrip(":\r\n")
        peer_hash = str(peer_hash)

        #  Update forwadlink and msgid
        mlock.acquire()
        peerlist.forwardlink[0] = sockfd
        peerlist.forwardlink[1] = peer_hash

        peerlist.msgid[peer_hash] = int(recv_msgid)
        mlock.release()

        #  Create thread to listen forwardlink message
        _run_fdlistener_ = True
        thread_listenforward = threading.Thread(name="Forwardlistener",
                                                target=listen_forwardlink,
                                                args=(sockfd, peer_hash,))
        thread_listenforward.start()

        insert_cmd("[Conc] Successful! A Forward link to user \"" +
                   peer_info[0] + '\"')
        print("[build_forwardlink]",
              "Recv id", recv_msgid,
              "\tCurrent peer msgid:", peerlist.msgid[peer_hash])

        return
    else:
        insert_cmd("[Conc] Failed! Try next...")
        return


def connect_to_forwardlink():
    """ Thread to check if forwardlink has been established or not """
    global mlock, _running_, peerlist, thread_listenforward, _run_fdlistener_

    #  Get the thread name
    thd_name = "Thd." + threading.current_thread().getName()
    print("[{}] Start...".format(thd_name))

    insert_cmd("[Conc] Finding a forward link...")

    #  DEBUG: Allow other peers to connect to me first
    time.sleep(5.0)

    while True:
        for i in range(5):
            time.sleep(0.5)

            if _running_ is False:
                print("[{}] is dying... x(".format(thd_name))
                return

        #  Check forwardlink connection, if no then build one!
        if peerlist.forwardlink[0] == None:
            insert_cmd("[Conc] No forward link is found, try again...")

            build_forwardlink()

            #  Print the current state on cmd
            peerlist.print_state()


def listen_to_port():
    """ Thread to listen connection(s) using select """
    global mlock, peerlist, listen_socket, _running_

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()
    print("[{}] Start...".format(thd_name))

    #  Start working
    insert_cmd("[Port] Now listening port " + str(listen_port))

    readsock_list = []
    readsock_list.append(listen_socket)

    while True:
        inready, outready, excready = select.select(readsock_list, [], [], 1.0)

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
                    data = s.recv(500)

                    if data:
                        #  At this stage only if the connection has been
                        #  established will the program enter following code
                        if data[:2] == "P:":
                            peerlist.request_update()

                            s.send("S:{}::\r\n".format(peerlist.my_msgid))

                            userinfo = data[2:].rstrip(":\r\n").split(':')
                            print("[{}] Received request message {}".format(
                                thd_name, userinfo))

                            peer_hash = sdbm_hash(userinfo[1] + userinfo[2] +
                                                  userinfo[3])

                            #  Add to backlink list and update msgid
                            mlock.acquire()
                            peerlist.backlinks.append([s, peer_hash])

                            hashval = str(peer_hash)
                            peerlist.msgid[hashval] = int(userinfo[4])
                            print("[listen_to_port] Update peer msgid to",
                                  peerlist.msgid[hashval])
                            mlock.release()

                            #  Inform user
                            insert_cmd("[Conc] User \"" + userinfo[1] + '\"'
                                       " (" + userinfo[2] + ":" + userinfo[3] +
                                       ") has connected to me")

                            print("[listen_to_port] Recve msgid: {}\t"
                                  "Current peer msgid: {}".format(
                                      int(userinfo[4]),
                                      peerlist.msgid[str(peer_hash)]
                                  ))

                            #  Print the state now
                            peerlist.print_state()
                        else:
                            print("[{}] Receive a message: {}".format(
                                thd_name, data
                            ))

                            peerlist.recv_msg(data)
                    else:
                        print("[{}] Broken connection from {}"
                              " removing...".format(thd_name, s.getpeername()))

                        mlock.acquire()
                        for i in peerlist.backlinks:
                            if i[0] == s:
                                insert_cmd("[Conc] Disconnect to " +
                                           str(s.getpeername()))

                                #  Remove it from backlinks and msgid
                                peerlist.backlinks.remove(i)
                                if str(i[1]) in peerlist.msgid:
                                    del peerlist.msgid[str(i[1])]
                        mlock.release()

                        readsock_list.remove(s)
                        s.close()

                        #  Print the state now
                        peerlist.request_update()
                        peerlist.print_state()


#
#  Functions to handle user input
#
def do_User():
    global username, roomname

    _un = userentry.get()

    if _un is "":
        showwarning("Please enter your name", "Your name must not be null!")
        return

    if ":" in _un:
        showwarning("Special character!", "Cannot contain \":\"")
        return
    elif roomname != "":
        insert_cmd("[User] You are NOT allowed to change you name, " +
                   username)
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

    server_socket.send("L::\r\n")
    received = server_socket.recv(500)

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
    elif roomname != "":
        insert_cmd("[Join] You have joined a chatroom " + roomname)
        return

    #  Send message to the server
    _KEEPALIVE_ = ("J:{:s}:{:s}:{:s}:{:d}::\r\n").format(_rm, username,
                                                         userip, listen_port)
    server_socket.send(_KEEPALIVE_)
    received = server_socket.recv(500)

    if received[:2] == "M:":
        #  Only delete user input if it has been successfully connected
        roomname = _rm
        _MYHASH_ = sdbm_hash(username + userip + str(listen_port))
        userentry.delete(0, END)

        #  Update the member list
        memberlist = received[2:].rstrip("::\r\n")
        print("[do_Join] Join trigger...", end="")
        peerlist.update(memberlist)

        insert_cmd("[Join] You have successfully joined the chatroom " +
                   roomname + " as \"" + username + "\"!\n" +
                   "       User(s) online: " +
                   str(len(peerlist.data)))

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
    elif received[:2] == "F:":
        error_msg = ("[Join] Error: {:s}").format(
            received[2:].rstrip(":\r\n"))
        insert_cmd(error_msg)


def do_Send():
    global mlock, peerlist

    message = userentry.get()
    peerlist.print_peerinfo()

    if message is "":
        showwarning("Please enter the message",
                    "The message must not be null!")
        return

    insert_msg(username, message)
    userentry.delete(0, END)

    #  Check if there is any link to send
    if peerlist.is_connected():
        mlock.acquire()
        peerlist.send_msg(message)
        time.sleep(0.01)
        mlock.release()

        print("[do_Send] Send message (ID: {}): {}".format(
            peerlist.my_msgid, message))


def do_Quit():
    global _running_, server_socket, listen_socket
    global thread_listenforward, _run_fdlistener_

    insert_cmd("[Quit] Shutting down...")
    _running_ = False
    _run_fdlistener_ = False

    if thread_listenforward is not None and thread_listenforward.is_alive():
        thread_listenforward.join()

    for t in thread_list:
        t.join()

    server_socket.close()
    listen_socket.close()
    sys.exit(0)


# Add buttons functions
def do_close():
    if askokcancel("Quit", "Do you want to quit?"):
        do_Quit()


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

    listen_socket.listen(10)

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

    win.protocol("WM_DELETE_WINDOW", do_close)
    win.mainloop()


if __name__ == "__main__":
    main(sys.argv)
