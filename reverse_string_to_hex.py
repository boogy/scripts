#!/usr/bin/python

import sys

try:
  input = sys.argv[1]
except IndexError:
  print "[-] You must supply a string to the script ...!"
  sys.exit(1)

print "String lenght : " + str(len(input))

stringList = [ input[i:i+4] for i in range(0, len(input), 4) ]

for item in stringList[::-1]:
  print item[::-1] + ' : ' + "0x" + str(item[::-1].encode('hex'))
