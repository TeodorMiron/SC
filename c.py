from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
import json
import socket
from Cryptodome.Util.Padding import unpad
from Cryptodome.Signature import pkcs1_15

BLOCK_SIZE = 128

class JSONObject:
  def __init__( self, dict ):
      vars(self).update( dict )

aesKey=get_random_bytes(16)
print(aesKey)

def client_program():
    host = socket.gethostname()  # as both code is running on same pc
    port = 5000  # socket server port number

    client_socket = socket.socket()  # instantiate
    client_socket.connect((host, port))  # connect to the server
    message=''
    while message.lower().strip() != 'bye':

        key = RSA.importKey(open('mykey.pem').read())
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(aesKey)
        message=ciphertext

        client_socket.send(message)  # send message
        ciphertext = client_socket.recv(1024)  # receive response

        cipher = AES.new(aesKey, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext, BLOCK_SIZE)
        print(plaintext)
        jsonobject = json.loads(plaintext, object_hook=JSONObject)
        text = bytes(jsonobject.sigSid, 'utf-8')
        text=text.decode()
        text=bytes.fromhex(text)

        print(text)

        key = RSA.import_key(open('public.key').read())
        t=bytes(str(jsonobject.sid), 'utf-8')
        hash2=SHA256.new(t)
        try:
            pkcs1_15.new(key).verify(hash2,text)
            print("valid")
        except(ValueError,TabError):
            print("invalid")




    client_socket.close()  # close the connection

client_program()