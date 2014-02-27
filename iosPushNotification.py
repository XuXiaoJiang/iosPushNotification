#!/usr/bin/python

import os, ast, ssl, json ,socket, struct, binascii, sys, getopt
from OpenSSL.crypto import *

def main(argv):

    #all parameter we may need
    keyFile = ''
    cerFile = ''
    keyPemFile = ''
    cerPemFile = ''
    pemFile = ''
    token = ''
    payload = json.dumps({"aps":{"alert":"default message","sound":"alert.aif"}})
    development = 1

    #parsering the arguments
    try:
         opts, args = getopt.getopt(argv,"hk:c:p:m:t:d:",["help", "keyFile=", "cerFile=", "KeyPemFile=", "cerPemFile=", "pemFile=", "token=", "payload=", "development="])
    except getopt.GetoptError:
        print 'please use iosPushNotification.py -h or iosPushNotification.py --help for help'
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print """
#######################--help--#######################
    -k --keyFile : for the p12 file. (no supported yet)
    -c --cerFile : for the cert file. (no supported yet)
    --keyPemFile : for pem file that generated from the p12 file. (no supported yet)
    --cerPemFile : for pem file that generated from the cert file. (no supported yet)
    --pemFile : the combined pem file, which is most widely used.
    -t --token : the token of device to receive this notification.
    -m --payload : the payload to be sent.
    -d --development : specified as 1 to send push notificaiont to staging server, 0 to send to produciton server, default as 1.
#####################################################
            """
            sys.exit()
        elif opt in ("-k", "--keyFile"):
            keyFile = arg
        elif opt in ("-c", "--cerFile"):
            cerFile = arg
        elif opt == "--keyPemFile":
            keyPemFile = arg
        elif opt == "--cerPemFile":
            cerPemFile = arg
        elif opt in ("-p", "--pemFile"):
            pemFile = arg
        elif opt in ("-t", "--token"):
            token = arg
        elif opt in ("-m", "--payload"):
            payload = json.dumps(arg)
        elif opt in ("-d", "--development"):
            development = arg

    # checking necessary paramenters
    if not token:
        print 'token is needed to send a push notification, pealse specified with '
        sys.exit(2)
    hasPem = (keyFile and cerFile) or (keyPemFile and cerPemFile) or pemFile
    if not hasPem:
        print 'key file and cert file is needed, you need to provided either original files or pem file'
        sys.exit(2)

    #sending push notification
    if pemFile:
        send_push_notification(token, payload, pemFile, dev = development == 1)
    elif keyPemFile and cerPemFile :
        pemFile = create_pem_file(keyPemFile, cerPemFile)


def create_pem_file(key, cert):
    if key.endswith(".p12") and cert.endswith(".cer") :
        print "original files"
    elif key.endswith(".pem") and cert.endswith(".pem") :
        print "pem files"
    else:
        print "plese using correct key file and cert file."
        return ""


def send_push_notification(token, payload, cert = "", dev = True):     
    # the certificate file generated from Provisioning Portal     
    if not cert:
        print("not pem to use")
        return()
    else :
        certfile = cert
    # APNS server address (use 'gateway.push.apple.com' for production server)
    if dev:
        apns_address = ('gateway.sandbox.push.apple.com', 2195)
        print "sending to staging"
    else :
        apns_address = ('gateway.push.apple.com', 2195)
 
    # create socket and connect to APNS server using SSL
    s = socket.socket()
    sock = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_SSLv3, certfile=certfile)
    sock.connect(apns_address)
 
    # generate APNS notification packet
    token = binascii.unhexlify(token)
    fmt = "!cH32sH{0:d}s".format(len(payload))
    cmd = '\x00'
    msg = struct.pack(fmt, cmd, len(token), token, len(payload), payload)
    sock.write(msg)
    sock.close()
    print("Notification sent successfully")
 
if __name__ == "__main__":
   main(sys.argv[1:])