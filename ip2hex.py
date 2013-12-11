#! /usr/bin/env python
# Many ways I founs to tranform the ip
# adress into hex to be used in shellcode
"""
Usage: ./ip2hex.py [ADDRESS]
Example:
./ip2hex.py 192.168.1.10
 C0A8010A
"""
import sys

def ip2hex0(ip):
    hex = ""
    for octet in ip.split("."):
        hex = "%s%02X " % (hex, int(octet))
    return hex

def ip2hex1(ip):
    hexIP = []
    [hexIP.append(hex(int(x))[2:].zfill(2)) for x in ip.split('.')]
    hexIP = " ".join(hexIP)
    return hexIP

def ip2hex2(ip):
  return "\\x" + "\\x".join(map(lambda x: hex(int(x))[2:].zfill(2), ip.split(".")))

def ip2hex3(ip):
  return "\\x" + "\\x".join(map(lambda x: "%02x" % int(x), ip.split(".")))

def main():
  print ip2hex0(sys.argv[1])
  print ip2hex1(sys.argv[1])
  print ip2hex2(sys.argv[1])
  print ip2hex3(sys.argv[1])

if __name__ == "__main__":
    sys.exit(main())
