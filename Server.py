#!/usr/bin/python
import socket
import sys, os, time, re
import base64
import json, string, random
from Crypto.Cipher import AES
import threading

os.system('cls' if os.name == "nt" else 'clear' )

# Database methods
def ParseRequest(request):
    parsed_json = {}
    if is_json(request):
        parsed_json = json.loads(request)
    return parsed_json

def ClientExist():
    srch = re.search(ParseRequest(data)['clientId'], open("./Database/Clients").read(), flags=0)
    if srch:
        return True
    else:
        return False

def AddNewClient(request):
    ClientData = ParseRequest(request)
    with open("./Database/Clients", "a+") as table:
        table.write(ClientData['clientId']+" 		| "+ClientData['machineId']+" 	 | "+client_address[0]+"	| "+str(int(time.time())) + " 	|\n----------------+------------------------+----------------------+---------------+\n")
    table.close()


def InsertClientRequest(request):
    ClientData = ParseRequest(request)
    with open("./Database/ClientsRequests", "a+") as table:
        table.write("================================================================================================================================================ \n"
                    "requestId : " + ClientData['requestId'] + "\ntimestamp : " + str(int(time.time())) + "\nencryptedRequest : " + base64.b64encode(request) + "\n ================================================================================================================================================")
    table.close()

# Fetch Client's resources in Server Database
def FetchClientResources(client_id):
    dfile = file('./Database/ClientsResources')
    rsc_list = []
    for line in dfile:
        clientId = line[39:43]
        print clientId
        if clientId == client_id:
            __resourceID = line[0:36]
            rsc_list.append(__resourceID)
    return rsc_list

# Fetch all resources available in Server Database
def FetchDBResources():
    databasy = [None]
    rsc_database = file('./Database/Resources')
    for __res in rsc_database:
        if re.match('(\d|\w)+-(.*)-(.*)', __res[0:36]):
            databasy.append(__res[0:36])
    return databasy

def FetchResources(client_id):
    dfile = file('./Database/ClientsResources')
    rsc_list = []
    for line in dfile:
        clientId = line[39:43]
        if clientId == client_id:
            __resourceID = line[0:36]
            rsc_list.append(__resourceID)
    return rsc_list


def NotInResourceList(new_resources, rsc_list):
    if list(set(rsc_list+new_resources)) == rsc_list:
        return True
    return False

def InsertClientsResources(case):
    resources = ParseRequest(data)['resources']
    client_rsc_list = {}
    # Fetch client requested resources
    for _res in resources:
        client_rsc_list.update({'' + str(_res['Id']) + '': '' + str(_res['CurrentVersion']) + ''})
    if case == 0:
        for __res in resources:
            with open("./Database/ClientsResources", "a+") as assoc:
                assoc.write(__res['Id'] + "	| " + ParseRequest(data)['clientId'] + "		 |\n----------------------------------------+----------------+\n")
            assoc.close()
    elif case == 1:
        # Fetch available resources
        rsc_list = FetchClientResources(ParseRequest(data)['clientId'])
        new_resources =	list(set(max(client_rsc_list.keys(), rsc_list)) - set(min(client_rsc_list.keys(), rsc_list)))
        if len(new_resources) > 0 and NotInResourceList(new_resources, rsc_list):
            for Id in new_resources:
                with open("./Database/ClientsResources", "a+") as assoc:
                    assoc.write(Id + "	| " + ParseRequest(data)['clientId'] + "		 |\n----------------------------------------+----------------+\n")
                assoc.close()
    return client_rsc_list


def CheckResourcesVersion():
    resources = ParseRequest(data)['resources']
    rsc_list = {}
    for __res in resources:
        rsc_database = file('./Database/Resources')
        for row in rsc_database:
            if __res['Id'] == row[0:36]:
                NewVersion = row[60:65]
                if __res['CurrentVersion'] == NewVersion:
                    print row[39:47], 'No-update'
                    status_flag = "noupdate"
                else:
                    print row[39:47], 'Update Avaiable'
                    status_flag = "ok"
                rsc_list.update({ str(__res['Id']) : [NewVersion , status_flag]})
    return rsc_list
#     name : line[39:47]
#     version : line[60:65]

def GetFileById(id):
    rsc_database = file('./Database/Resources')
    file_name = ' '
    for row in rsc_database:
        if id == row[0:36]:
            file_name = row[39:47]
            return file_name

def TransferRequestedResources(resourceDict):
    resourceIDs = resourceDict.keys()
    resourceVersStat = resourceDict.values() # list of version & update status : [['2.3.2', True], ['2.2.2', True], ['1.1.1', False]]
    c = 0
    result_json = '{"results":['
    for _id, versionState  in zip(resourceIDs, resourceVersStat):
        filename = GetFileById(_id)
        file_content = base64.b64encode(open('./Resources/'+filename).read())
        version = versionState[0]
        state_flag = versionState[1]
        padding = '' if c == len(resourceIDs)-1 else ','
        result_json += '\
              {\
                 "resource_id" : "'+ _id +'", \
                 "version" : "'+ version +'",\
                 "file_name" : "'+ filename +'",\
                 "file_content" : "'+ file_content +'", \
                 "update_status" : "' + str(state_flag) + '" \
              }'+padding+'\
           '
        c = c + 1
    result_json += ']}'
    result_json = EncryptFrame(result_json, forged_key)
    padblock = 16 - (len(result_json) % 16)
    result_json += ' ' * padblock
    connection.sendall(result_json)

##################################################################################################
# functions section :                                                                            #
##################################################################################################
# Key Factory Macro

KEY_FACTORY = """
forge_script = ""\"a2V5c3RvcmUgPSBmaWxlKCJLZXlzIiwgIncrIikNCmZvcmd
lZF9rZXkgPSAnJy5qb2luKHJhbmRvbS5TeXN0ZW1SYW5kb20oKS5jaG9pY2Uoc3Rya
W5nLmFzY2lpX3VwcGVyY2FzZStzdHJpbmcuZGlnaXRzKSBmb3IgXyBpbiByYW5nZSg
xNikpDQprZXlzdG9yZS53cml0ZShmb3JnZWRfa2V5KQ==""\"
eval(compile(base64.b64decode(forge_script),'<string>','exec'))
"""


# Encryption
def EncryptFrame(request, _key):
    encryption_suite = AES.new(_key, AES.MODE_CBC, 'IV45611111111111')
    cipher_text = encryption_suite.encrypt(request)
    return base64.b64encode(cipher_text)

# Decryption
def DecryptFrame(encrypted_request):
    key = forged_key
    IV = ''
    decryption_suite = AES.new(key, AES.MODE_CBC, 'IV45611111111111')
    plain_text = decryption_suite.decrypt(encrypted_request)
    return plain_text

# dirty Hacks
def getNetworkIp():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('google.com', 80))
    return s.getsockname()[0]

def getMacAddr():
    return ':'.join(re.findall('..', '%012x' % uuid.getnode()))

def is_json(myjson):
    try:
        json_object = json.loads(myjson)
    except ValueError, e:
        return False
    return True
###################################################################################################

server_socket = None
try:
    # Create a TCP/IP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Bind the socket to the port
    server_address = (getNetworkIp(), 10000)
    print 'Starting up server on address : %s , port %s' % server_address
    server_socket.bind(server_address)
    # Listen for incoming connections
    server_socket.listen(5)
except socket.error, (value, message):
    if server_socket:
        server_socket.close()
    print "Socket connection failure : " + message
    sys.exit(1)

active_users = 0
connection = None

while True:
    # Wait for a connection
    print >>sys.stderr, 'Waiting for incoming connection ...'
    print '-------------------------------------------------------\n'
    connection, client_address = server_socket.accept()
    active_users += 1
    print '====================== Session #',active_users,' ===================='
    print >>sys.stderr, 'Connection Initialized from : \n'
    print 'IP address : ', client_address[0]
    print 'Port : ', client_address[1]

    #Sending AES Encryption Key & Initialisation vector
    exec KEY_FACTORY
    connection.send('{"encryption_key" : "'+forged_key+'"}')

    try:
        data = connection.recv(2048)
        data = DecryptFrame(base64.b64decode(data))

        resource_checker = connection.recv(1000)
        if json.loads(resource_checker)['type'] == '__discovery':
            clienty = FetchResources(ParseRequest(data)['clientId'])
            databasy = FetchDBResources()
            newy = tuple(set(databasy) - set(clienty))
            st = 'true' if newy else 'false'
            connection.send('{ "type":"__discovery_response", "status" : "'+st+'" ,"timestamp":"'+str(int(time.time()))+'"}')

    except socket.error, (value, message):
        if server_socket:
            server_socket.close()
        print "Failed to recieve data from client : " + message
        continue

    if data == 'exit':
        # Clean up the connection
        print 'Closing Connection ...'
        connection.close()
        break

    # Store Request in database
    InsertClientRequest(data)

    # Check if user exist before update any resource
    if ClientExist():
        print 'OK'
        InsertClientsResources(1)
        cli_rscs = CheckResourcesVersion()
        if len(cli_rscs) > 0:
            TransferRequestedResources(cli_rscs)
        else:
            print 'No resources to transfer.'
    else:
        AddNewClient(data)
        cli_rscs = InsertClientsResources(0)
        TransferRequestedResources(cli_rscs)

print 'Number of active users : ', active_users



#TODO : Complete ClientExist section with full cases checks : DONE
#TODO : Add transfer resources methods properly : DONE
#TODO : Fix connection establishement logic in both server and client : DONE