#!/usr/bin/python
# Output a string that can be used directly in asembly
#
import sys

try:
  input = sys.argv[1]
except IndexError:
  print "[-] You must supply a string to the script ...!"
  sys.exit(1)

# Reverse the string
rev_input = input[::-1]

# Encode it in hex
rev_input_hex = rev_input.encode('hex')

print "\n[+] Hex string : \n" + rev_input_hex
print "\n[+] asm output:"
for item in map( "".join, zip(*[iter(rev_input_hex)]*8)):
  print "push 0x" + item

print
