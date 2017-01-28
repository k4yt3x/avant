#!/usr/bin/python3

# -*- coding: utf-8 -*-

"""
     _                 _              _
    / \    __   __    / \     _ __   | |
   / _ \   \ \ / /   / _ \   | '_ \  | __|
  / ___ \   \ V /   / ___ \  | | | | | |
 /_/   \_\   \_/   /_/   \_\ |_| |_|  \__|

Name: Project AvAnt
Author: K4YT3X
Version: 1.0
Date: 1/28/2017

Licensed under the GNU General Public License Version 3 (GNU GPL v3),
    available at: https://www.gnu.org/licenses/gpl-3.0.txt

(C) 2017 K4YT3X

Desctiption: AvAnt is a network utility environment. It makes network related
actions much faster than tratitional commands

Do whatever you want to do with this program, hopefully this will make your
life easier. However, REGARDLESS WHAT YOU DO WITH IT, THE DEVELOPER WILL NOT
BE RESPONSIBLE FOR IT. THEREFORE, USE IT UNDER YOUR OWN RESPINSIBILITY.

"""

import psutil
import argparse
import socket
import multiprocessing


# ------------------------------ Classes Defined ------------------------------

class ccm():
    """
        This Class defines some output styles and
        All UNIX colors
    """

    # Define Global Color
    global W, R, G, LG, OR, Y, B, P, C, GR, H, BD, NH
    # Console colors
    # Unix Console colors
    W = '\033[0m'  # white (normal / reset)
    R = '\033[31m'  # red
    G = '\033[32m'  # green
    LG = '\033[92m'  # light green
    OR = '\033[33m'  # orange
    Y = '\033[93m'  # yellow
    B = '\033[34m'  # blue
    P = '\033[35m'  # purple
    C = '\033[96m'  # cyan
    GR = '\033[37m'  # grey
    H = '\033[8m'  # hidden
    BD = '\033[1m'  # Bold
    NH = '\033[28m'  # not hidden

    def __init__(self, arg):
        super(ccm, self).__init__()
        self.arg = arg

    def info(msg):
        print(G + '[+] INFO: ' + str(msg) + W)

    def warning(msg):
        print(Y + BD + '[!] WARNING: ' + str(msg) + W)

    def error(msg):
        print(R + BD + '[!] ERROR: ' + str(msg) + W)

    def debug(msg):
        print(R + BD + '[*] DBG: ' + str(msg) + W)


# ------------------------------ Functions Defined ------------------------------

def icon():
    print(R + BD + '    _     ' + W + '        ' + R + BD + '    _     ' + W + '         _   ' + W)
    print(R + BD + '   / \    ' + W + '__   __ ' + R + BD + '   / \    ' + W + ' _ __   | |_ ' + W)
    print(R + BD + '  / _ \   ' + W + '\ \ / / ' + R + BD + '  / _ \   ' + W + '| \'_ \  | __|' + W)
    print(R + BD + ' / ___ \  ' + W + ' \ V /  ' + R + BD + ' / ___ \  ' + W + '| | | | | |_ ' + W)
    print(R + BD + '/_/   \_\ ' + W + '  \_/   ' + R + BD + '/_/   \_\ ' + W + '|_| |_|  \__|\n' + W)


def process_arguments():
    """
    This funtion takes care of all arguments
    """
    global args
    parser = argparse.ArgumentParser()
    action_group = parser.add_argument_group('ACTIONS')
    action_group.add_argument("-s", "--sftp", help="-f, --sftp: Connect SFTP", action="store_true", default=False)
    action_group.add_argument("-d", "--debug", help="-d, --debug: Debug port connection and decryption; decrypt port but don't connect", action="store_true", default=False)

    args = parser.parse_args()


def show_connections():
    """
        Gets all client to server and server to client connections
        Will return and print all connections
    """
    print(G + BD + '\n       [LOCAL]                          ' + Y + BD + '[REMOTE]\n' + W)
    t_length = 52
    for connection in psutil.net_connections():
        try:
            lhost, lport = connection.laddr
            rhost, rport = connection.raddr
            lhost, lport, rhost, rport = str(lhost), str(lport), str(rhost), str(rport)
            content = '  ' + lhost + ':' + lport + '  >  ' + rhost + ':' + rport
            print_length = len(content)
            dashes = (t_length - print_length) * '-'
            print(LG + '  ' + lhost + W + ':' + Y + lport + W + '  ' + dashes + '>  ' + OR + rhost + W + ':' + Y + rport + W)
        except ValueError:
            pass
    print()


def print_open(host, port):
    t_length = 38
    host, port = str(host), str(port)
    content = '   ' + host + '  ' + '>  ' + port
    print_length = len(content)
    dashes = (t_length - print_length) * '-'
    print('   ' + LG + host + ' ' + W + dashes + '>  ' + Y + port)


def opened_ports():
    """
        Print and return all opened local ports, including port binded to
        0.0.0.0 and 127.0.0.1 and other local ip
    """
    print(G + BD + '\n   [ADDRESS]                    ' + Y + BD + '[PORT]' + W)
    for connection in psutil.net_connections():
        host, port = connection.laddr
        status = connection.status
        if host == '0.0.0.0' or host == '127.0.0.1':
            if status == 'LISTEN':
                print_open(host, port)
    print()


def listen_local(port):

    def listen():
        while True:
            data = conn.recv(1024)
            if not data:
                ccm.info('Connection closed by remote host')
                break
            else:
                print(data.decode().strip('\n'))
        conn.close()
        sock0.close()

    port = str(port)
    port = int(port)
    ccm.info('Listening on Localhost: ' + str(port))
    sock0 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock0.bind(('0.0.0.0', port))
    sock0.listen(1)
    conn, (addr, port) = sock0.accept()
    ccm.info('Connected from ' + str(addr) + ':' + str(port))

    try:
        lp = multiprocessing.Process(target=listen)
        lp.start()
        while True:
            msg = input().strip('\n')
            conn.send(msg.encode())
    except KeyboardInterrupt:
        ccm.info('Closing socket connection')
        lp.terminate()
        conn.close()
        sock0.close()
        ccm.info('Closed!')


def cmd():
    """
        A command line environment
    """
    while True:
        cmd = input(OR + 'Avant> ' + W).strip(' ').upper()
        if cmd == 'HELP':
            print()
            print(Y + BD + 'l' + R + '[port]' + Y + ':' + W + ' Listen on localhost on [port]')
            print(Y + BD + 'SHOW PORTS ' + R + '/' + Y + ' PORTS: ' + W + 'Show all listening ports')
            print(Y + BD + 'SHOW CONNECTINOS ' + R + '/' + Y + ' CONS: ' + W + 'Show all network connections')
            print()
        elif cmd == 'SHOW PORTS' or cmd == 'PORTS':
            opened_ports()
        elif cmd == 'SHOW CONNECTIONS' or cmd == 'CONS':
            show_connections()
        elif cmd[0] == 'L':
            port = cmd[1:]
            try:
                port = int(port)
            except ValueError:
                ccm.error('Please Enter a valid port number! (1~65535)')
                continue
            if port > 65535:
                ccm.error('Please Enter a valid port number! (1~65535)')
            else:
                listen_local(port)
        elif cmd == 'EXIT' or cmd == 'QUIT' or cmd == 'BYE':
            print(OR + '\n[+] AVN: Quitting AvAnt...' + W)
            print(OR + '[+] AVN: Bye!\n' + W)
            exit(0)
        else:
            ccm.error('Invalid Input!')


# ------------------------------ Procedural Code ------------------------------

try:
    icon()
    print('      Type "help" to print help page\n')
    cmd()
except KeyboardInterrupt:
    print(OR + '\n[+] AVN: Quitting AvAnt...' + W)
    print(OR + '[+] AVN: Bye!\n' + W)
    exit(0)
except Exception as er:
    ccm.error('Error Detected!')
    ccm.error(str(er))
    exit(1)
