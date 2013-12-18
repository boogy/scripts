#!/usr/bin/env python
# encoding: utf-8

import os
import sys
import argparse
import smtplib
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import formatdate
from email import Encoders

COMMASPACE = ','

def send_mail(send_from, send_to, subject, text, files=[], server="localhost"):
    assert type(send_to)==list
    assert type(files)==list

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject
    msg.attach( MIMEText(text) )

    for f in files:
        part = MIMEBase('application', "octet-stream")
        part.set_payload( open(f,"rb").read() )
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(f))
        msg.attach(part)

    smtp = smtplib.SMTP(server)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()

if __name__ == "__main__":
    desc  = "Send email with attachement file(s)"
    parser = argparse.ArgumentParser(description=desc, add_help=True)
    parser.add_argument('--version', action='version', version='%(prog)s 2.0')
    parser.add_argument('-d', '--from', action='store', dest='from_email', help='the email of the sender')
    parser.add_argument('-t', '--to', action='store', dest='to_email',nargs='+', help='email addresse(s) to send to separated by commas')
    parser.add_argument('-s', '--subject', action='store', dest='subject', help='subject of the email')
    parser.add_argument('-b', '--body', action='store', dest='body', help='the body/text message of the email')
    parser.add_argument('-f', '--file', dest='file',default=[], nargs='+', help='files to send in attachement')
    parser.add_argument('-m', '--server', dest='server',default="localhost", help='mail server to use (default:localhost)')
    opt = parser.parse_args()

    if len(sys.argv)== 1:
        parser.print_help()
        sys.exit(1)

    files   = []
    send_to = []

    send_from = opt.from_email
    subject   = opt.subject
    server    = opt.server
    text      = opt.body

    [files.append(f) for f in opt.file]
    [send_to.append(e) for e in opt.to_email]

    send_mail(send_from, send_to, subject, text, files, server)
#EOF
