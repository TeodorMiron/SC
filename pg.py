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



class JSONObject:
  def __init__( self, dict ):
      vars(self).update( dict )


BLOCK_SIZE = 128

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            key = RSA.importKey(open('mykey.pem').read())
            cipher = PKCS1_OAEP.new(key)
            message = cipher.decrypt(data)
            print(message)
            aesKey = message
            ciphertext = conn.recv(6024)
            cipher = AES.new(aesKey, AES.MODE_ECB)
            plaintext = cipher.decrypt(ciphertext)
            plaintext = unpad(plaintext, BLOCK_SIZE)
            print(plaintext)
            jsonobject2 = json.loads(plaintext, object_hook=JSONObject)
            jsonobject3 = json.loads(jsonobject2.PM, object_hook=JSONObject)
            print(jsonobject3)
            print(bytes.fromhex(jsonobject3))

