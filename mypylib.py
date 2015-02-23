#!/usr/bin/env python
# -*- coding: utf8 -*-
#
# A python file with useful functions to be able
# to find them as fast as possible when needed
#
from __future__ import print_function
import os
import re
import sys
import time
import select
import pprint
import struct
import capstone
import subprocess


def chunks(l, n):
    """ Yield successive n-sized chunks from l"""
    for i in xrange(0, len(l), n):
        yield l[i:i+n]


def run_check_return(host, cmd):
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host)
    stdin, stdout, stderr = client.exec_command(cmd)
    return stdout.channel.recv_exit_status()    # status is 0 if OK


def threaded(f, daemon=True):
    """Function decorator to use threading"""
    import threading
    import Queue
    def wrapped_f(q, *args, **kwargs):
        """this function calls the decorated function and puts the
        result in a queue"""
        ret = f(*args, **kwargs)
        q.put(ret)

    def wrap(*args, **kwargs):
        """this is the function returned from the decorator. It fires off
        wrapped_f in a new thread and returns the thread object with
        the result queue attached"""
        q = Queue.Queue()
        t = threading.Thread(target=wrapped_f, args=(q,)+args, kwargs=kwargs)
        t.setDaemon(daemon)
        t.setName(args[2])
        print "[+] Starting thread name %s daemon %s" % (t.name, t.isDaemon())
        t.start()
        t.result_queue = q
        return t
    return wrap


def parseCfg(cfg, section):
    """Get the data from the config file and return a dictionary"""
    import ConfigParser
    dict1 = {}
    Config = ConfigParser.ConfigParser()
    Config.read(cfg)
    options = Config.options(section)
    for option in options:
        try:
            dict1[option] = Config.get(section, option)
            if dict1[option] == -1:
                DebugPrint("skip: %s" % option)
        except:
            print >> sys.stderr, "exception on %s!" % option
            dict1[option] = None
    return dict1


def colorize(text, color=None, attrib=None):
    """Colorize text using ansicolor
    ref: https://github.com/hellman/libcolors/blob/master/libcolors.py"""
    # ansicolor definitions
    COLORS = {"black": "30", "red": "31", "green": "32", "yellow": "33",
              "blue": "34", "purple": "35", "cyan": "36", "white": "37"}
    CATTRS = {"regular": "0", "bold": "1", "underline": "4", "strike": "9",
              "light": "1", "dark": "2", "invert": "7"}
    CPRE = '\033['
    CSUF = '\033[0m'
    ccode = ""
    if attrib:
        for attr in attrib.lower().split():
            attr = attr.strip(",+|")
            if attr in CATTRS:
                ccode += ";" + CATTRS[attr]
    if color in COLORS:
        ccode += ";" + COLORS[color]
    return CPRE + ccode + "m" + text + CSUF


def green(text, attrib=None):
    """Wrapper for colorize(text, 'green')"""
    return colorize(text, "green", attrib)


def red(text, attrib=None):
    """Wrapper for colorize(text, 'red')"""
    return colorize(text, "red", attrib)


def yellow(text, attrib=None):
    """Wrapper for colorize(text, 'yellow')"""
    return colorize(text, "yellow", attrib)


def blue(text, attrib=None):
    """Wrapper for colorize(text, 'blue')"""
    return colorize(text, "blue", attrib)


def msg(text, color=None, attrib=None, teefd=None):
    """Generic pretty printer with redirection"""
    if isinstance(text, str) and "\x00" not in text:
        print(colorize(text, color, attrib))
        if teefd:
            print(colorize(text, color, attrib), file=teefd)
    else:
        pprint.pprint(text)
        if teefd:
            pprint.pprint(text, teefd)


def error(text):
    """Colorize error message with prefix"""
    msg(colorize("[-] Error: %s" % text, "red", "bold"))


def debug(text):
    """Colorize debug message with prefix"""
    msg(colorize("[+] Debug: %s" % text, "blue", "bold"))


def status(text):
    """Colorize status with prefix"""
    msg(colorize("[+] Status: %s" % text, "yellow", "bold"))


def success(text):
    """Colorize success with prefix"""
    msg(colorize("[+] Success: %s" % text, "green", "bold"))


def die(s=None, e=None, exit_code=-1):
    """Exits the program with an error string and optionally prints an exception."""
    if s:
        msg(colorize("FATAL: %s" % s, "red", 'bold'))
    if e:
        msg(colorize("The exception was: ", "red"))
        sys.stderr.write(str(e) + '\n')
        sys.stderr.flush()
    sys.exit(exit_code)


def read(path):
    """Open file, return content."""
    path = os.path.expanduser(os.path.expandvars(path))
    with open(path) as fd:
        return fd.read()


def bytes2human(n):
    """Convert number to human readable form"""
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i+1)*10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return '%.1f%s' % (value, s)
    return "%sB" % n


def tmpfile(pref="lalib-"):
    """Create and return a temporary file with custom prefix"""
    import tempfile
    return tempfile.NamedTemporaryFile(prefix=pref)


def is_printable(text, printables=""):
    """Check if a string is printable"""
    return (set(str(text)) - set(string.printable + printables) == set())


def bash(cmd, cmd_input=None, timeout=None, return_stderr=False):
    """Execute cmd and return stdout and stderr in a tuple"""
    p = subprocess.Popen(['/bin/bash', '-c', cmd],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE)
    if timeout is None:
        o, e = p.communicate(cmd_input)
    else:
        t = time.time()
        while time.time() - t < timeout:
            time.sleep(0.01)
            if p.poll() is not None:
                break
        if p.returncode is None:
            p.kill()
        o, e = p.communicate()
    if return_stderr:
        return o, e
    return o


def normalize_argv(args, size=0):
    """Normalize argv to list with predefined length"""
    args = list(args)
    for (idx, val) in enumerate(args):
        if to_int(val) is not None:
            args[idx] = to_int(val)
        if size and idx == size:
            return args[:idx]
 
    if size == 0:
        return args
    for i in range(len(args), size):
        args += [None]
    return args


def to_hexstr(str):
    """Convert a string to hex escape represent"""
    return "".join(["\\x%02x" % ord(i) for i in str])
 
 
def to_hex(num):
    """Convert a number to hex format"""
    if num < 0:
        return "-0x%x" % (-num)
    else:
        return "0x%x" % num
 
 
def to_address(num):
    """Convert a number to address format in hex"""
    if num < 0:
        return to_hex(num)
    if num > 0xffffffff:  # 64 bit
        return "0x%016x" % num
    else:
        return "0x%08x" % num
 
 
def to_int(val):
    """Convert a string to int number"""
    try:
        return int(str(val), 0)
    except:
        return None
 
 
def str2hex(str):
    """Convert a string to hex encoded format"""
    result = str.encode('hex')
    return result
 
 
def hex2str(hexnum):
    """Convert a number in hex format to string"""
    if not isinstance(hexnum, str):
        hexnum = to_hex(hexnum)
    s = hexnum[2:]
    if len(s) % 2 != 0:
        s = "0" + s
    result = s.decode('hex')[::-1]
    return result
 
 
def int2hexstr(num, intsize=4):
    """Convert a number to hexified string"""
    if intsize == 8:
        if num < 0:
            result = struct.pack("<q", num)
        else:
            result = struct.pack("<Q", num)
    else:
        if num < 0:
            result = struct.pack("<l", num)
        else:
            result = struct.pack("<L", num)
    return result


def list2hexstr(intlist, intsize=4):
    """Convert a list of number/string to hexified string"""
    result = ""
    for value in intlist:
        if isinstance(value, str):
            result += value
        else:
            result += int2hexstr(value, intsize)
    return result
 
 
def str2intlist(data, intsize=4):
    """Convert a string to list of int"""
    result = []
    data = data.decode('string_escape')[::-1]
    l = len(data)
    data = ("\x00" * (intsize - l % intsize) +
            data) if l % intsize != 0 else data
    for i in range(0, l, intsize):
        if intsize == 8:
            val = struct.unpack(">Q", data[i:i + intsize])[0]
        else:
            val = struct.unpack(">L", data[i:i + intsize])[0]
        result = [val] + result
    return result
 
 
def convert_hex_to_ascii(h):
    """Convert hexadecimal to printable ascii
    Usage:
        print convert_hex_to_ascii(0x6e69622f)
    """
    chars_in_reverse = []
    while h != 0x0:
        chars_in_reverse.append(chr(h & 0xFF))
        h = h >> 8
    chars_in_reverse.reverse()
    return ''.join(chars_in_reverse)


def get_interfaces():
    """Gets all (interface, IPv4) of the local system."""
    d = subprocess.check_output('ip -4 -o addr', shell=True)
    ifs = re.findall(r'^\S+:\s+(\S+)\s+inet\s+([^\s/]+)', d, re.MULTILINE)
    return [i for i in ifs if i[0] != 'lo']


def write(path, data, create_dir=False):
    """Create new file or truncate existing to zero length and write data."""
    path = os.path.expanduser(os.path.expandvars(path))
    if create_dir:
        path = os.path.realpath(path)
        ds = path.split('/')
        f = ds.pop()
        p = '/'
        while True:
            try:
                d = ds.pop(0)
            except:
                break
            p = os.path.join(p, d)
            if not os.path.exists(p):
                os.mkdir(p)
    with open(path, 'w') as f:
        f.write(data)


def bitstr(n, width=None):
    """Return the binary representation of n as a string and optionally
    zero-fill (pad) it to a given length
    ex:
        >>> bitstr(123)
        >>> '1111011'
    """
    result = list()
    while n:
        result.append(str(n % 2))
        n = int(n / 2)
    if (width is not None) and len(result) < width:
        result.extend(['0'] * (width - len(result)))
    result.reverse()
    return ''.join(result


def which(name, all = False):
    """which(name, flags = os.X_OK, all = False) -> str or str set
 
    Works as the system command ``which``; searches $PATH for ``name`` and
    returns a full path if found.
 
    If `all` is :const:`True` the set of all found locations is returned, else
    the first occurence or :const:`None` is returned.
 
    Args:
      `name` (str): The file to search for.
      `all` (bool):  Whether to return all locations where `name` was found.
 
    Returns:
      If `all` is :const:`True` the set of all locations where `name` was found,
      else the first location or :const:`None` if not found.
 
    Example:
      >>> which('sh')
      '/bin/sh'
    """
    import stat
    isroot = os.getuid() == 0
    out = set()
    try:
        path = os.environ['PATH']
    except KeyError:
        log.error('Environment variable $PATH is not set')
    for p in path.split(os.pathsep):
        p = os.path.join(p, name)
        if os.access(p, os.X_OK):
            st = os.stat(p)
            if not stat.S_ISREG(st.st_mode):
                continue
            # work around this issue: http://bugs.python.org/issue9311
            if isroot and not \
              st.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                continue
            if all:
                out.add(p)
            else:
                return p
    if all:
        return out
    else:
        return None


def chunk(iterable, chunk_size):
    """Divide iterable into chunks of chunk_size"""
    for i in range(0, len(iterable), chunk_size):
        yield iterable[i:i + chunk_size]


def xor(s1, s2):
    return "".join([chr(ord(s1[i]) ^ ord(s2[i])) for i in range(len(s1))])
 
 
def xor_strings(xs, ys):
    return "".join(chr(ord(x) ^ ord(y)) for x, y in zip(xs, ys))


def contains_not(x, bad):
    return not any(c in bad for c in x)


def contains_only(x, good):
    return all(c in good for c in x)


def capstone_dump(code, arch=capstone.CS_ARCH_X86, mode=capstone.CS_MODE_32, cols="abm"):
    md = capstone.Cs(arch, mode)
    for i in md.disasm(code, 0x1000):
        line = ""
        if "a" in cols:
            line += "0x%04x: " % i.address
    if "b" in cols:
        line += "%-20s " % " ".join("%02x" % x for x in i.bytes)
    if "m" in cols:
        line += "%s %s" % (i.mnemonic, i.op_str)
    print line

def x86_disas(code, **kw):
    capstone_dump(code, capstone.CS_ARCH_X86, capstone.CS_MODE_32, **kw)


def x86_64_disas(code, **kw):
    capstone_dump(code, capstone.CS_ARCH_X86, capstone.CS_MODE_64, **kw)


def can_read(s, timeout=0):
    x,_,_ = select.select([s], [], [], timeout)
    return x != []

def flatten(nested_list):
    """Dismount a nested list in one simples list
    >>> flatten([[1,2,3], [4,5,6], [7,8,9]])
    [1, 2, 3, 4, 5, 6, 7, 8, 9]

    It works with a map too:
    >>> flatten(map(lambda x: [x], range(10)))
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    
    similar to:
    return [item for sublist in nested_list for item in sublist]
    
    :nested_list: a list object with another lists as elements
    :returns: a list object
    """
    return list(itertools.chain(*nested_list))
