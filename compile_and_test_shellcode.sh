#!/bin/bash
#
# Author : tuxgeek.org
#
# Give it a .asm asembly file to compile and specify the architecture
# that you want to compile'it for [32] or [64]
# Usage:
#
#  compile_and_test_shellcode.sh execve-shell 32
#

FILE=$1
ARCH=$2
SHELLCODE=""

if test -z $ARCH ; then
  A=$(uname -p)
  case $A in
    "x86_64")
      ARCH=64;;
    "i386")
      ARCH=32;;
    "i686")
      ARCH=32;;
    "*")
      echo "Unsupported architecture"
  esac
fi

function compile()
{
  if echo $ARCH|egrep -qo "64" ; then
    nasm -f elf64 $1.asm -o $1.o
    ld -o $1 $1.o    
  elif echo $ARCH|egrep -qo "32" ; then
    nasm -f elf32 $1.asm -o $1.o
    ld -m elf_i386 $1.o -o $1
  fi
  
  SHELLCODE=$(objdump -d $1.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '| \
  tr '\t' ' '|sed 's/ $//g'|sed 's/ /\\x/g'|paste -d '' -s |sed 's/^/"/'|sed 's/$/"/g')
  
  echo
  echo "[+] Multiline hellcode:"
  echo "$SHELLCODE" | grep -o -P "([0-9a-zA-Z\\\]){96}"|sed 's/^\\/\"\\/'|sed 's/.$/&\"/'
  echo
  echo "[+] One line shellcode:"
  echo "$SHELLCODE"
  echo
}


function write_shellcode_c()
{
  c_file=$1
  s_code=$2
  cat << __EOF__ > ${c_file}_shellcode.c
#include <stdio.h>
#include <string.h>

char shellcode[] = \\
$(echo ${2}|grep -o -P "([0-9a-zA-Z\\\]){96}"|sed 's/^\\/\"\\/'|sed 's/.$/&\"/');

int main()
{
  /*
  int *ret;
  printf("Shellcode Lenght: %d\n", strlen(shellcode));
  ret = (int *)&ret + 2;
  (*ret) = (int)shellcode;
  */
  
  printf("Shellcode Lenght: %d\n", strlen(shellcode));
  int (*ret)() = (int(*)())shellcode;
  ret();  
}
__EOF__
  
  if echo $ARCH|egrep -qo "64"
  then
    gcc -fno-stack-protector -z execstack ${c_file}_shellcode.c -o ${c_file}_shellcode
  elif echo $ARCH|egrep -qo "32"
  then
    #gcc -m32 -fno-stack-protector -z execstack ${c_file}_shellcode.c -o ${c_file}_shellcode
    gcc -fno-stack-protector -z execstack ${c_file}_shellcode.c -o ${c_file}_shellcode
  fi
    
}

compile $FILE
write_shellcode_c $FILE $SHELLCODE
echo "[+] Files :"
ls -l|egrep --color=auto ${c_file}

#EOF
