#!/usr/bin/env python
# -*- coding: utf8 -*-
#
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
