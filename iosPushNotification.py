#!/usr/bin/python

import os, ast, ssl, json ,socket, struct, binascii, sys, getopt, random, string
from OpenSSL.crypto import *

def main(argv):

    #all parameter we may need
    keyFile = ''
    cerFile = ''
    keyPemFile = ''
    cerPemFile = ''
    pemFile = ''
    token = ''
    payload = '{"aps":{"alert":"default message","sound":"alert.aif"}}'
    development = 1
    generatePemFile = 0

    #parsering the arguments
    try:
         opts, args = getopt.getopt(argv,"hk:c:p:m:t:d:",["help", "keyFile=", "cerFile=", "keyPemFile=", "cerPemFile=", "pemFile=", "token=", "payload=", "development=", "generatePemFile="])
    except getopt.GetoptError:
        print ('please use iosPushNotification.py -h or iosPushNotification.py --help for help')
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print ("""
#######################--help--#######################
    -k --keyFile : for the p12 file.
    -c --cerFile : for the cert file.
    --keyPemFile : for pem file that generated from the p12 file.
    --cerPemFile : for pem file that generated from the cert file.
    --pemFile : the combined pem file, which is most widely used.
    -t --token : the token of device to receive this notification.
    -m --payload : the payload or the file path of payload to be sent.
    -d --development : specified as 1 to send push notificaiont to staging server, 0 to send to produciton server, default as 1.
    --generatePemFile : generate the pem file, name it as same as keyFile's name
#####################################################
            """)
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
            payload = arg
        elif opt in ("-d", "--development"):
            development = arg
        elif opt in ("--generatePemFile"):
            generatePemFile = arg

    if (os.path.isfile(payload)):
        payload = open(payload, "r").read()
    payload = json.dumps(json.JSONDecoder().decode(payload))
    print payload
    # checking necessary paramenters
    if not token:
        print ('token is needed to send a push notification, pealse specified with ')
        sys.exit(2)
    hasPem = keyFile or (keyPemFile and cerPemFile) or pemFile
    if not hasPem:
        print ('key file and cert file is needed, you need to provided either original files or pem file')
        sys.exit(2)

    #sending push notification
    if pemFile :
        send_push_notification(token, payload, pemFile, dev = development == 1)
    elif keyPemFile and cerPemFile :
        pemFile = create_pem_file(keyPemFile, cerPemFile)
        send_push_notification(token, payload, pemFile, dev = development == 1)
        os.remvoe(pemFile)
    elif keyFile :
        pemFile = create_pem_file(keyFile, cerFile)
        send_push_notification(token, payload, pemFile, dev = development == 1)
        if (generatePemFile):
            fileName = keyFile[:-4] + ".pem"
            print (fileName)
            os.rename(pemFile, fileName)
        else :
            os.remove(pemFile)



def create_pem_file(key, cert):
    if key.endswith(".p12") and not cert :
        print("single p12 file")
        p12File = open(key, "r")
        pemFilePath = "iosPushNotification.temp" + random_string(6)
        while (os.path.isfile(pemFilePath + ".pem")):
            pemFilePath = "iosPushNotification.temp" + random_string(6)
        pemFilePath = pemFilePath + ".pem"
        pemFile = open(pemFilePath, "w")
        p12 = load_pkcs12(p12File.read(), "")
        pemFile.write(dump_certificate(FILETYPE_PEM,p12.get_certificate()))
        pemFile.write(dump_privatekey(FILETYPE_PEM,p12.get_privatekey()))
        pemFile.close()
        return pemFilePath
    elif key.endswith(".p12") and cert.endswith(".cer") :
        keyFile = open(key, "r")
        cerFile = open(cert, "r")
        pemFilePath = "iosPushNotification.temp" + random_string(6)
        while (os.path.isfile(pemFilePath + ".pem")):
            pemFilePath = "iosPushNotification.temp" + random_string(6)
        pemFilePath = pemFilePath + ".pem"
        pemFile = open(pemFilePath, "w")
        p12 = load_pkcs12(keyFile.read(), "")
        x509 = load_certificate(FILETYPE_ASN1, cerFile.read())
        pemFile.write(dump_certificate(FILETYPE_PEM,x509))
        pemFile.write(dump_privatekey(FILETYPE_PEM,p12.get_privatekey()))
        pemFile.close()
        return pemFilePath
    elif key.endswith(".cer") and cert.endswith(".cer") :
        keyFile = open(key, "r")
        cerFile = open(cert, "r")
        pemFilePath = "iosPushNotification.temp" + random_string(6)
        while (os.path.isfile(pemFilePath + ".pem")):
            pemFilePath = "iosPushNotification.temp" + random_string(6)
        pemFilePath = pemFilePath + ".pem"
        pemFile = open(pemFilePath, "w")
        p12 = load_privatekey(FILETYPE_ASN1, cerFile.read())
        x509 = load_certificate(FILETYPE_ASN1, cerFile.read())
        pemFile.write(dump_certificate(FILETYPE_PEM,x509))
        pemFile.write(dump_privatekey(FILETYPE_PEM,x509))
        pemFile.close()
        return pemFilePath
    elif key.endswith(".pem") and cert.endswith(".pem") :
        keyPemFile = open(key, "r")
        cerPemFile = open(cert, "r")
        pemFilePath = "iosPushNotification.temp" + random_string(6)
        while (os.path.isfile(pemFilePath + ".pem")):
            pemFilePath = "iosPushNotification.temp" + random_string(6)
        pemFilePath = pemFilePath + ".pem"
        pemFile = open(pemFilePath, "w")
        pemFile.write(keyPemFile.read())
        pemFile.write(cerPemFile.read())
        pemFile.close()
        return pemFilePath
    else:
        print ("plese using correct key file and cert file.")
        return ""

def random_string(length):
    return "".join(random.choice(string.ascii_uppercase + string.digits) for x in range(length))

def send_push_notification(token, payload, cert = "", dev = True):     
    # the certificate file generated from Provisioning Portal     
    if not cert:
        print("not pem found")
        return()
    else :
        certfile = cert
    # APNS server address (use 'gateway.push.apple.com' for production server)
    if dev:
        apns_address = ('gateway.sandbox.push.apple.com', 2195)
        print ("sending to staging")
    else :
        apns_address = ('gateway.push.apple.com', 2195)
 
    # create socket and connect to APNS server using SSL
    s = socket.socket()
    sock = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1, certfile=certfile)
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