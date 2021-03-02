from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
import json
import socket
import random
import base64

from Cryptodome.Util.Padding import pad
from Cryptodome.Signature import pkcs1_15
BLOCK_SIZE = 128

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

        conn.close()




server_program()