#!/bin/bash
# Give it a .asm asembly file to compile and specify the architecture
# that you want to compile'it for [32] or [64]
# Usage:
#
#  compile_and_test_shellcode.sh execve-shell 32
#

function compile()
{
  if echo $ARCH|egrep -qo "64" ; then
    nasm -f elf64 ${FILE_NAME}.${FLE_EXT} -o $FILE_NAME.o
    ld -o $1 $1.o    
  elif echo $ARCH|egrep -qo "32" ; then
    nasm -f elf32 ${FILE_NAME}.${FILE_EXT} -o $FILE_NAME.o
    ld -m elf_i386 $FILE_NAME.o -o $FILE_NAME
  fi
  
  SHELLCODE=$(objdump -d $FILE_NAME.o|grep '[0-9a-f]:'|grep -v 'file'|cut -f2 -d:|cut -f1-6 -d' '|tr -s ' '| \
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

char shellcode[] = 
$(echo ${s_code});

int main()
{
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

SHELLCODE=""

if test -z $2 ; then
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

FILE_NAME="${1%.*}"
FILE_EXT="${1##*.}"

compile $FILE_NAME
write_shellcode_c $FILE_NAME $SHELLCODE
echo "[+] Files :"
ls -l|egrep --color=auto ${c_file}

#EOF
