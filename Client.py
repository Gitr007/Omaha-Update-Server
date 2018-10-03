#!/usr/bin/python
import socket
import sys, os
import json
import re, uuid
import hashlib
import time, random, base64, string
import threading
from Crypto.Cipher import AES

# os.system('cls' if os.name == "nt" else 'clear' )


##################################################################################################
# Database methods :                                                                             #
##################################################################################################
def ParseServerRequest(serv_request):
    parsed_json = {}
    if is_json(serv_request):
        parsed_json = json.loads(serv_request)
    return parsed_json


def UpdateClientResourceDatabase():
    GlobalResources = ParseServerRequest(decrypted_server_response[0])['results']
    cli_rsc_database = file(r'~/Omaha Simulation/Database/Resources')

    lines = cli_rsc_database.readlines()
    for _res in GlobalResources:
        flag = _res['update_status']
        if flag == "ok":
            ID = str(_res['resource_id'])
            Nversion = str(_res['version'])
            ctr = 0
            for cli in lines:
                if ctr > 2 and ctr % 2 != 0:
                    if cli[0:36] == ID:
                        lines[ctr] = cli.replace(cli[60:65], Nversion)
                ctr = ctr + 1
    file(r'~/Omaha Simulation/Database/Resources', 'w+').writelines(lines)


def UpdateResourceFiles():
    resources = ParseServerRequest(decrypted_server_response[0])['results']
    for _res in resources:
        flag = _res['update_status']
        if flag == "ok":
            fname = str(_res['file_name'])
            content = base64.b64decode(str(_res['file_content']))
            path = r'~/Omaha Simulation/Resources'+fname
            open(path, 'w+').write(content)

def ___SendUpdateCheckerRequest():
    # setting resource files
    DatabaseEntries = file(r'~/Omaha Simulation/Database/Resources').readlines()
    DBlen = len(DatabaseEntries) - 2
    MAC = getMacAddr()
    count = 0
    # Generate request parameters
    request_id = hashlib.md5(str(int(time.time()))).hexdigest()
    user_id = '1108' # str(sum(bytearray(MAC)))
    request = '{ \
           "requestId": "' + request_id + '",\
           "clientId": "' + user_id + '",\
           "machineId": "' + MAC + '",\
           "resources": ['
    for resource_record in DatabaseEntries:
        id_check = re.match('(\d|\w)+-(.*)-(.*)', resource_record[0:36])
        if id_check:
            padding = '' if count == DBlen else ','
            request += '\
                  {\
                      "Id": "' + resource_record[0:36] + '",\
                      "CurrentVersion": "' + resource_record[60:65] + '"\
                  }' + padding + '\
               '
        count = count + 1
    request += ']\
        }'
    padblock = 16 - (len(request) % 16)
    request += ' ' * padblock
    print request
    enc_request = EncryptFrame(request, json.loads(secure_info[0])['encryption_key'])
    client_socket[0].sendall(enc_request)

def ResourceDiscoveryPackets():
    request = '{"type" : "__discovery", "timestamp" : "'+str(int(time.time()))+'"}'
    client_socket[0].sendall(request)
    threading.Timer(120, ResourceDiscoveryPackets).start()

##################################################################################################
# functions section :                                                                            #
##################################################################################################

def getMacAddr():
    return ':'.join(re.findall('..', '%012x' % uuid.getnode()))

def is_json(myjson):
    try:
        json_object = json.loads(myjson)
    except ValueError, e:
        return False
    return True

# Encryption
def EncryptFrame(request, _key):
    encryption_suite = AES.new(_key, AES.MODE_CBC, 'IV45611111111111')
    cipher_text = encryption_suite.encrypt(request)
    return base64.b64encode(cipher_text)

# Decryption
def DecryptFrame(encrypted_request):
    key = json.loads(secure_info[0])['encryption_key']
    IV = ''
    decryption_suite = AES.new(key, AES.MODE_CBC, 'IV45611111111111')
    plain_text = decryption_suite.decrypt(encrypted_request)
    return plain_text
##################################################################################################

client_socket = [None]
secure_info = [None] # change variable to mutable type, fiiiinek a C/C++, finkom a pointers
decrypted_server_response = [None]

def Updater():
    try:
        # Create a TCP/IP socket
        client_socket[0] = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect the socket to the port where the server is listening
        server_address = ('192.168.100.150', 10000)
        print 'Connecting to %s port %s' % server_address
        # initiate connection to the remote server
        client_socket[0].connect(server_address)
    except socket.error, (value, message):
        if client_socket[0]:
            client_socket[0].close()
        print "Socket connection failure : " + message
        sys.exit(1)

    secure_info[0] = client_socket[0].recv(125)
    print secure_info
    # Update Checker Request
    ___SendUpdateCheckerRequest()


    while True:
        # Send data
        # message = raw_input("root@client:~# ")
        message = 'exit'
        time.sleep(20)

        #  Send discovery packets, checking for new resources
        ResourceDiscoveryPackets()

        discovery_resp = client_socket[0].recv(1024)
        # if json.loads(discovery_resp)['status'] == 'true':

        # Recieve file from server
        server_response = client_socket[0].recv(2048)
        decrypted_server_response[0] = DecryptFrame(base64.b64decode(server_response))

        UpdateClientResourceDatabase()
        UpdateResourceFiles()

        if message == 'exit':
            client_socket[0].sendall('exit')
            print "Connection Reset by remote Server ...\n"
            break

        print message

    client_socket[0].close()

"""
resources used IDS :
record1 : 8A69D345-D564-463C-AFF1-A69D9E530F96
record2 : 430FD4D0-B729-4F61-AA34-91526481799D
"""

#TODO : Socket programming, create Network between Client and Server : DONE
#TODO : Define Communication Protocol Measures ( Message Format JSON...) : DONE
#TODO : Setup client database ( Resources ) , send from / update in database : DONE
#TODO : Exception Handling sockets , Encrypt requests and responses ( end-to-end encryption ): DONE
