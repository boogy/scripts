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
