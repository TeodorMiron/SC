from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
import json
import socket
import random
import base64

from Cryptodome.Util.Padding import pad
from Cryptodome.Util.Padding import unpad
from Cryptodome.Signature import pkcs1_15
BLOCK_SIZE = 128

class Card:
    CardN=''
    CardExp=''
    CCode=''
    Sid=''
    Amount=''
    PunKC=''
    NC=''
    M=''

class JSONObject:
  def __init__( self, dict ):
      vars(self).update( dict )

class mesage1:
    sid=''
    sigSid=''

mmesage1=mesage1()

def server_program():
    # get the hostname
    host = socket.gethostname()
    port = 5000  # initiate port no above 1024

    server_socket = socket.socket()  # get instance
    # look closely. The bind() function takes tuple as argument
    server_socket.bind((host, port))  # bind host address and port together

    # configure how many client the server can listen simultaneously
    server_socket.listen(2)
    conn, address = server_socket.accept()  # accept new connection
    print("Connection from: " + str(address))
    while True:
        # receive data stream. it won't accept data packet greater than 1024 bytes
        data = conn.recv(1024)

        key = RSA.importKey(open('mykey.pem').read())
        cipher = PKCS1_OAEP.new(key)
        message = cipher.decrypt(data)
        print(message)
        aesKey=message

        Sid=random.randrange(1000,10000)
        print(Sid)
        mmesage1.sid=Sid

        Sid = bytes(str(Sid), 'utf-8')
        key=RSA.import_key(open('private.key').read())
        hash=SHA256.new(Sid)

        signn=pkcs1_15.new(key)
        signature=signn.sign(hash)
        print(signature)
        mmesage1.sigSid=signature.hex()
        print("da")
        print(mmesage1.sigSid)
        jsonStr = json.dumps(mmesage1.__dict__)
        res = bytes(jsonStr, 'utf-8')

        res=pad(res,BLOCK_SIZE)
        cipher = AES.new(aesKey, AES.MODE_ECB)
        ciphertext = cipher.encrypt(res)

        conn.send(ciphertext)

        ciphertext  = conn.recv(5096)

        cipher = AES.new(aesKey, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext, BLOCK_SIZE)
        #print(plaintext)

        jsonobject = json.loads(plaintext, object_hook=JSONObject)
        jsonobject2 = jsonobject.PM
        jsonobject2 = bytes.fromhex(jsonobject2)

        cipher = AES.new(aesKey, AES.MODE_ECB)
        plaintext = cipher.decrypt(jsonobject2)
        plaintext = unpad(plaintext, BLOCK_SIZE)
        print(plaintext)
        jsonobject2 = json.loads(plaintext, object_hook=JSONObject)
        jsonobject2 = json.loads(jsonobject2.CardInfo, object_hook=JSONObject)
        myCard = Card()
        myCard.Card = jsonobject2.Card
        myCard.CardExp = jsonobject2.CardExp
        myCard.CCode = jsonobject2.CCode
        myCard.Sid = jsonobject2.Sid
        myCard.Amonut = jsonobject2.Amonut
        myCard.PunKC = jsonobject2.PunKC
        myCard.NC = jsonobject2.NC
        myCard.M = jsonobject2.M

        conn_to_pg(plaintext, aesKey)




class PG4:
    Sid = ''
    PunKC = ''
    Amount = ''
myPG4 = PG4()

class PG23:
    PM = ''
    SigM = ''


myPG23 = PG23()

def conn_to_pg(plaintext, aesKey):
    HOST2 = '127.0.0.1'  # The server's hostname or IP address
    PORT2 = 65432  # The port used by the server

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST2, PORT2))
        jsonobject2 = json.loads(plaintext, object_hook=JSONObject)
        jsonobject2 = json.loads(jsonobject2.CardInfo, object_hook=JSONObject)
        myCard = Card()
        myCard.Card = jsonobject2.Card
        myCard.CardExp = jsonobject2.CardExp
        myCard.CCode = jsonobject2.CCode
        myCard.Sid = jsonobject2.Sid
        myCard.Amonut = jsonobject2.Amonut
        myCard.PunKC = jsonobject2.PunKC
        myCard.NC = jsonobject2.NC
        myCard.M = jsonobject2.M

        key = RSA.importKey(open('mykey.pem').read())
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(aesKey)
        message = ciphertext

        s.send(message)  # send message
        myPG4.Sid = jsonobject2.Sid
        myPG4.Amonut = jsonobject2.Amonut
        myPG4.PunKC = jsonobject2.PunKC
        jsonStr = json.dumps(myPG4.__dict__)
        Sid = bytes(jsonStr, 'utf-8')
        key = RSA.import_key(open('private.key').read())
        hash = SHA256.new(Sid)
        signn = pkcs1_15.new(key)
        signature = signn.sign(hash)
        jsonStr3 = json.dumps(myCard.__dict__)
        myPG23.PM = jsonStr3
        myPG23.SigM = signature.hex()


        print('asd', plaintext)



        jsonStr = json.dumps(myPG23.__dict__)
        res = bytes(jsonStr, 'utf-8')
        res = pad(res, BLOCK_SIZE)
        cipher = AES.new(aesKey, AES.MODE_ECB)
        ciphertext = cipher.encrypt(res)

        s.send(ciphertext)

        #data = s.recv(1024)



server_program()