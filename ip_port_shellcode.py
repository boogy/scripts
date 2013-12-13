#!/usr/bin/python
#
# IP & Port to shellcode
#
# Matt Jones - 24/08/2013 - matt.jones.85[@]gmail.com

import sys

def convert2hex(ip, port):	

	# convert ip to hex
	ip = ip.split(".")
	ip = ' '.join((hex(int(i)) for i in ip)).split(" ")
	hexip = []
	for i in ip:
		if len(i) == 3:
			i = i.replace("0x","0x0")
		hexip += i
	
	hexip = ''.join(hexip).replace("0x","\\x")
	
	# convert port to hex
	port = hex(int(port)).replace("0x","")
	if len(port) == 3:
		port = "0" + port

	counter = 0
	mesh = ""
	hexport = ""
	for i in port:
		mesh = mesh + i
		counter = counter + 1
		if counter == 2:
			hexport = hexport + "\\x" + mesh
			mesh = ""
			counter = 0
	
	return hexip, hexport
	
if __name__ == '__main__':
	
	try:
		ip = sys.argv[1]
		port = sys.argv[2]
	except IndexError:
		print "\nUsage:\n\npython ip2hex.py IP PORT\n"
		sys.exit(1)
	
	hexip, hexport = convert2hex(ip, port)
	print "[+] IP:", hexip
	print "[+] Port:", hexport
