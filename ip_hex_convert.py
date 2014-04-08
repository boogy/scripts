#!/usr/bin/env python
# encoding: utf-8
#
# Convert ip, port to hex and back to text
#

import sys
import argparse


def to_hex(s):
    return " ".join("0x" + "{0:x}".format(ord(c)).zfill(2) for c in s) # <-- Python 3 is OK

def ip2hex(ip):
    try:
        hex_reverse  = "0x" + "".join(map(lambda x: hex(int(x))[2:].zfill(2), ip.split(".")))
        hex_nreverse = "0x" + "".join(map(lambda x: hex(int(x))[2:].zfill(2), ip.split(".")[::-1]))
        hex_opcodes  = "".join(map(lambda x: "\\x%02x" % int(x), ip.split(".")))
        print "== IP =="
        print "Hex reverse    : %s\t\t(%s)" % (hex_reverse, hex2ip(hex_reverse.replace('0x', '')))
        print "Hex non reverse: %s\t\t(%s)" % (hex_nreverse, hex2ip(hex_nreverse.replace('0x','')))
        print "Hex opcodes    : %s\t(%s)" % (hex_opcodes, opt.ip)
    except ValueError as e:
        print "\n[-] You probably gave a bad value for the IP !"
        print "[-] ERROR: %s" % e
        sys.exit(2)


def hex2ip(ip):
    try:
        return '.'.join(str(int(i, 16)) for i in reversed([ip[i:i+2] for i in range(0, len(ip), 2)]))
    except ValueError as e:
        print "\n[-] You probably gave a bad value for the IP !"
        print "[-] ERROR: %s" % e
        sys.exit(2)


def port2hex(port):
    try:
        port_hex     = hex(int(port)).replace("0x", "")
        port_hex_op  = [ port_hex[i:i+2] for i in range(0, len(port_hex), 2) ]
        port_hex_op  =  "".join("\\x" + x for x in port_hex_op)
    except ValueError as e:
        print "\n[-] You probably gave a bad value for the port!"
        print "[-] ERROR: %s" % e
        sys.exit(2)
    return ( port_hex_op, port_hex)

def hex2port(port):
    try:
        return int(str(port), 16)
    except ValueError as e:
        print "\n[-] You probably gave a bad value for the port !"
        print "[-] ERROR: %s" % e
        sys.exit(2)

if __name__ == "__main__":
    desc  = "Convert ip to hex and back to text"
    parser = argparse.ArgumentParser(description=desc, add_help=True)
    parser.add_argument('-x', '--hex', action="store_true", help='convert ip to hex')
    parser.add_argument('-t', '--text', action="store_true", help='convert hex ip to text')
    parser.add_argument('-i', '--ip', dest="ip", help='the ip address to convert')
    parser.add_argument('-p', '--port', dest="port", help='the network port to convert')
    opt = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if opt.hex and opt.text:
        print "[-] You can't use hex and text options at the same time"
        print "[-] Use -x or -t serapately"
        sys.exit(1)

    if opt.hex and opt.ip:
        ip2hex(opt.ip)

    if opt.ip and opt.text:
        print "IP  : %s" % hex2ip(opt.ip)

    if opt.port and opt.text:
        print "PORT: %s" % hex2port(opt.port)

    if opt.port and opt.hex:
        port_hex_op, port_hex = port2hex(opt.port)
        print "== PORT =="
        print "Hex string  : 0x%s\t(%s)" % (port_hex, opt.port)
        print "Hex opcodes : %s\t(%s)"   % (port_hex_op, opt.port)

#EOF
