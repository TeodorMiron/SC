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

class respone:
    Rep=''
    Sid=''
    Sign=''

class sign:
    Rep=''
    Sid=''
    Amount=''
    NC=''
signature=sign()

responeR=respone()

aesKeyKPG=get_random_bytes(16)

BLOCK_SIZE = 128

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)



        data = conn.recv(1024)
        key = RSA.importKey(open('mykey.pem').read())
        cipher = PKCS1_OAEP.new(key)
        message = cipher.decrypt(data)
        print(message)
        aesKeyKM = message

        key = RSA.importKey(open('mykey.pem').read())
        cipher = PKCS1_OAEP.new(key)
        ciphertext = cipher.encrypt(aesKeyKPG)
        message = ciphertext

        conn.send(message)



        ciphertext = conn.recv(6024)
        cipher = AES.new(aesKeyKPG, AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        plaintext = unpad(plaintext, BLOCK_SIZE)
        print(plaintext)
        jsonobject2 = json.loads(plaintext, object_hook=JSONObject)
        jsonobject3 = json.loads(jsonobject2.PM, object_hook=JSONObject)
        SigM = jsonobject2.SigM
        print(jsonobject3.Card)
        print(bytes.fromhex(SigM))

        responeR.Sid=jsonobject3.Sid
        responeR.Rep="1"

        signature.Rep=responeR.Rep
        signature.Sid=responeR.Sid
        signature.Amount=jsonobject3.Amonut
        signature.NC=jsonobject3.NC

        jsonStr = json.dumps(signature.__dict__)
        Sid = bytes(jsonStr, 'utf-8')
        key = RSA.import_key(open('private.key').read())
        hash = SHA256.new(Sid)
        signn = pkcs1_15.new(key)
        signature = signn.sign(hash)

        responeR.Sign=signature.hex()

        jsonStr = json.dumps(responeR.__dict__)
        Sid = bytes(jsonStr, 'utf-8')
        res = pad(Sid, BLOCK_SIZE)
        cipher = AES.new(aesKeyKM, AES.MODE_ECB)
        ciphertext = cipher.encrypt(res)
        conn.send(ciphertext)








