#!/usr/bin/python

"""
Student name and No. : LEI WAN HONG, 3035202750
Student name and No. : HO KA KUEN,
Development platform : Mac OS X 10.11.3
Python version       : Python 2.7.10
Version              : 0.7d
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
thread_listenforward = None

_running_ = True
_run_fdlistener_ = False
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
    global _MYHASH_, server_socket, roomname, username, _running_

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

    def is_connected(self):
        if len(self.backlinks) > 0 or self.forwardlink[1] != None:
            return True
        else:
            return False

    def print_state(self):
        if self.is_connected():
            insert_cmd("[Conc] You are connected to peer(s)")
        else:
            insert_cmd("[Conc] Your are disconnected!")

    def print_msg(self, username, msg, recv_msgid):
        #  DEBUG: Printing
        print("[print_msg] Receive message in forward link")

        print("[print_msg] Received msgid: {}\tCurrent msgid: {}".format(
           recv_msgid, self.msgid
        ))

        if recv_msgid > int(self.msgid):
            print("[print_msg] msgid: ({} > {}),"
                  " print and update msgid...".format(recv_msgid, self.msgid))

            #  Print it on the screen
            insert_msg(username, msg)
            self.msgid = recv_msgid

            print("[print_msg] New msgid =", self.msgid)

    def send_msg(self, msg):
        #  print("Type of msgid is int?", type(self.msgid) is int)
        self.msgid += 1

        print("[debug] Current msgid =", self.msgid)
        msg_cmd = "T:{}:{}:{}:{}:{}:{}::\r\n".format(
            roomname, _MYHASH_, username, self.msgid,
            len(msg), msg.encode("base64", "strict")
        )

        print(msg_cmd)

        if self.backlinks != []:
            for sock in self.backlinks:
                sock[0].send(msg_cmd)

        if self.forwardlink[1] != None:
                self.forwardlink[0].send(msg_cmd)

    def recv_msg(self, msg):
        #  Split into list [roomname, hash, username, msgid, length, content]
        #  Decode the message
        msg = msg[2:].rstrip(":\r\n").split(':')
        msg[5] = msg[5].decode("base64", "strict")

        print(msg)

        if msg[0] != roomname:
            insert_cmd("[Error] Receive different chatrooms message!")
            return

        _backlink_hash = [x[1] for x in self.backlinks]

        #  TODO: Flooding message
        if str(msg[1]) == str(self.forwardlink[1]):
            self.print_msg(msg[2], msg[5], int(msg[3]))

        if int(msg[1]) in _backlink_hash:
            self.print_msg(msg[2], msg[5], int(msg[3]))

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
        """ It differs from above as it sends a keepalive message """
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

    def try_peerpos(self):
        global _running_

        self.request_update()

        #  Only 1 user then quit
        if len(self.data) == 1:
            return -1

        #  Let the position be peerpos and get it hashval
        peerpos = (self.pos + 1) % len(self.data)
        peer_hash = member_list.data[peerpos][1]

        #  Generate backlink hashval
        backlink_hash = [x[1] for x in self.backlinks]

        #  Try next peer if its hash values is
        #      1. equal to my hashval <=> equal to myself
        #      2. equal to forwardlink
        #      3. is in the backlink
        while (peer_hash == _MYHASH_ or
               peer_hash == self.forwardlink[1] or
               peer_hash in backlink_hash):

            #  After updated to 1 user then break the loop
            #  It is necessary since there is a case that
            #  a forwardlink just leave after the update
            if len(self.data) == 1:
                return -1
            #  if 2 users then wait for 2s and retry
            elif len(self.data) == 2:
                insert_cmd("[Conc] Waiting 2s for another user")
                time.sleep(2.0)
                self.request_update()

                if _running_ is False:
                    break

                continue

            peer_info = self.data[peerpos][0].split(':')

            #  DEBUG: Info printing
            print("[try_peerpos] Try pos.:", peerpos)
            print("[try_peerpos] Peerinfo:", peer_info)
            print("[try_peerpos] Equal to forwardlink[1]?",
                  peer_hash == self.forwardlink[1])
            print("[try_peerpos] In backlink?", peer_hash in backlink_hash)
            print("[try_peerpos] Peerhash:", peer_hash)
            print("[try_peerpos] backlink_hash:", backlink_hash, '\n')

            #  Add 1 to peerpos and retry
            peerpos = (peerpos + 1) % len(self.data)

            #  Need to update and retry
            self.request_update()
            backlink_hash = [x[1] for x in self.backlinks]
            peer_hash = member_list.data[peerpos][1]

        return peerpos


#  Create a memberlist
member_list = MemberList()


def send_keepalive():
    """ Thread to send keepalive message and update memberlist """
    global mlock, _running_, _KEEPALIVE_, member_list

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()
    print("[{}] Start...".format(thd_name))

    while True:
        #  DEBUG: hardcore sleep time
        #  for i in range(_SLEEPTIME_):
        for i in range(40):
            time.sleep(0.5)

            if _running_ is False:
                print("[{}] is dying... x(".format(thd_name))
                return

        member_list.request_update()


def listen_forwardlink(sockfd):
    """ Thread to receive message from the connected forward link """
    global mlock, member_list, _run_fdlistener_

    #  Get thread name
    thd_name = "Thd." + threading.current_thread().getName()
    print("[{}] Start...".format(thd_name))

    #  Set timeout for the socket
    sockfd.settimeout(0.1)

    while _run_fdlistener_:
        try:
            msg = sockfd.recv(1024)
        except socket.timeout:
            continue

        if msg:
            print("[{}] Recive message: {}".format(thd_name, msg))

            mlock.acquire()
            member_list.recv_msg(msg)
            mlock.release()

    sockfd.close()
    print("[{}] is dying... x(".format(thd_name))
    return


def build_forwardlink():
    """ Function to establish a forward link """
    global mlock, _MYHASH_, member_list, thread_listenforward, _run_fdlistener_
    global roomname, username, userip, listen_port, _running_

    #  Get the peer position
    pos = member_list.try_peerpos()

    #  Check if there exists any user
    if pos == -1:
        insert_cmd("[ERRO] You are the only user in the chatroom :(")
        return

    #  Get the necessary info now
    peer_info = member_list.data[pos][0].split(':')
    peer_hash = member_list.data[pos][1]
    print("[P2P] Try pos.:", pos)
    print("[P2P] Peerinfo:", peer_info)

    #  Build a socket and try to connect it!
    sockfd = socket.socket()
    sockfd.settimeout(1.0)

    try:
        insert_cmd("[Conc] Connecting \"{}\" with address {}:{}".format(
            peer_info[0], peer_info[1], peer_info[2]
        ))

        sockfd.connect((peer_info[1], int(peer_info[2])))
        sockfd.send("P:{}:{}:{}:{}:{}::\r\n".format(
            roomname, username, userip, listen_port, member_list.msgid
        ))
        response = sockfd.recv(512)
    except socket.timeout as e:
        print("[P2P]", e)
        insert_cmd("[Conc] " + str(e) + ". Update list and" +
                   " try again...")

        #  Timeout, connection lost?
        member_list.request_update()
        sockfd.close()
        return

    #  Receive success message from peer
    if response[:2] == "S:":
        _rcev_msgid = response[2:].rstrip(":\r\n")

        insert_cmd("[Conc] Successful! A Forward link to user \"" +
                   peer_info[0] + '\"')
        print("[P2P] Recve msgid: {}\tCurrent msgid: {}".format(
            _rcev_msgid, member_list.msgid
        ))

        #  Update to the newest msgid
        if _rcev_msgid > member_list.msgid:
            member_list.msgid = int(_rcev_msgid)

        #  Update forwadlink
        mlock.acquire()
        member_list.forwardlink[0] = sockfd
        member_list.forwardlink[1] = peer_hash
        mlock.release()

        #  Create thread to listen forwardlink message
        _run_fdlistener_ = True
        thread_listenforward = threading.Thread(name="Forwardlistener",
                                                target=listen_forwardlink,
                                                args=(sockfd,))
        thread_listenforward.start()

        return
    else:
        insert_cmd("[Conc] Failed! Try next...")
        sockfd.close()
        return


def connect_to_forwardlink():
    """ Thread to check if forwardlink has been established or not """
    global mlock, _running_, member_list, thread_listenforward, _run_fdlistener_

    #  Get the thread name
    thd_name = "Thd." + threading.current_thread().getName()
    print("[{}] Start...".format(thd_name))

    insert_cmd("[Conc] Finding a forward link...")

    #  DEBUG: Allow other peers to connect to me first
    time.sleep(5.0)

    while _running_:
        for i in range(5):
            time.sleep(0.5)

            if _running_ is False:
                print("[{}] is dying... x(".format(thd_name))
                return

        #  Check forwardlink connection, if no then build one!
        if member_list.forwardlink[0] == None:
            insert_cmd("[Conc] No forward link is found, try again...")

            build_forwardlink()

            member_list.print_state()
        #  Test if it is still connected
        else:
            #  Set timeout so that we will not wait forever
            member_list.forwardlink[0].settimeout(1.0)

            try:
                data = member_list.forwardlink[0].recv(512)
            except socket.timeout:
                continue

            #  Oh need to find new one!
            if not data:
                insert_cmd("[Conc] Forward link is broken, build again...")

                _run_fdlistener_ = False
                thread_listenforward.join()

                mlock.acquire()
                member_list.forwardlink[0] = None
                member_list.forwardlink[1] = None
                mlock.release()

                build_forwardlink()

                #  Print connection state to the user
                member_list.print_state()


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
                        #  established will the program enter following code
                        if data[:2] == "P:":
                            member_list.request_update()

                            s.send("S:{}::\r\n".format(member_list.msgid))

                            userinfo = data[2:].rstrip(":\r\n").split(':')
                            print("[{}] Received request message {}".format(
                                thd_name, userinfo))

                            _hashpeer = sdbm_hash(userinfo[1] + userinfo[2] +
                                                  userinfo[3])

                            print("[debug] Recve msgid: {}\t"
                                  "Current msgid: {}".format(
                                      int(userinfo[4]), member_list.msgid
                                  ))

                            #  Update to newest msgid
                            if int(userinfo[4]) > member_list.msgid:
                                print("[debug] Update msgid to", userinfo[4])
                                member_list.msgid = int(userinfo[4])

                            #  Add to backlink list for sending
                            mlock.acquire()
                            member_list.backlinks.append([s, _hashpeer])
                            mlock.release()

                            #  Inform user
                            insert_cmd("[Conc] User \"" + userinfo[1] + '\"'
                                       " (" + userinfo[2] + ":" + userinfo[3] +
                                       ") has connected to me")

                            #  Print the state now
                            member_list.print_state()
                        else:
                            print("[{}] Receive a message: {}".format(
                                thd_name, data
                            ))

                            mlock.acquire()
                            member_list.recv_msg(data)
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

                        #  Print the state now
                        member_list.request_update()
                        member_list.print_state()


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

    #  Only update roomname if it has passed the bove conditions
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
    if member_list.is_connected():
        mlock.acquire()
        member_list.send_msg(message)
        mlock.release()

        print("[debug] Send message (ID: {}): {}".format(
            member_list.msgid, message))


def do_Quit():
    global mlock, _running_, server_socket, listen_socket, member_list
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
