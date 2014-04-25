#!/usr/bin/env python
# encoding: utf-8

import sys

try:
  input = sys.argv[1].replace('0x', '')
except IndexError:
  print "[-] You must supply a string to the script ...!"
  sys.exit(1)

#print "String lenght " + str(len(input))

s = [ input[i:i+2] for i in range(0, len(input), 2) ]

for item in s[::-1]:
	sys.stdout.write("\\x" + item)
