from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
import json
import socket
from Cryptodome.Util.Padding import unpad
from Cryptodome.Util.Padding import pad
from Cryptodome.Signature import pkcs1_15

BLOCK_SIZE = 128

class JSONObject:
  def __init__( self, dict ):
      vars(self).update( dict )




class PO:
    OrderDesc = ''
    Sid = ''
    Amount = ''
    NC = ''

myPo = PO()

myPo.OrderDesc = 'muraturi'
myPo.Amount='4'
myPo.NC='NC'

class Card:
    CardN=''
    CardExp=''
    CCode=''
    Sid=''
    Amount=''
    PunKC=''
    NC=''
    M=''

class CardSID:
    CardInfo = ''
    CardS = ''


class POSID:
    PM=''
    POINFO = ''
    POS = ''

myPOSID = POSID()

my_CardSID = CardSID()


aesKey=get_random_bytes(16)
print(aesKey)

myCard = Card()
myCard.Card='1111222233334444'
myCard.CardExp='02/22'
myCard.CCode = '123'
myCard.Sid = ''
myCard.Amonut='73'
myCard.PunKC= aesKey.hex()
myCard.NC='NC'
myCard.M='M'

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
            myCard.Sid = str(jsonobject.sid)
            myPo.Sid = str(jsonobject.sid)
        except(ValueError,TabError):
            print("invalid")



        jsonStr = json.dumps(myCard.__dict__)
        my_CardSID.CardInfo = jsonStr

        Sid = bytes(jsonStr, 'utf-8')
        key = RSA.import_key(open('private.key').read())
        hash = SHA256.new(Sid)

        signn = pkcs1_15.new(key)
        signature = signn.sign(hash)
        my_CardSID.CardS = signature.hex()

        PoJS = json.dumps(myPo.__dict__)
        myPOSID.POINFO = PoJS
        Sid = bytes(jsonStr, 'utf-8')
        key = RSA.import_key(open('private.key').read())
        hash = SHA256.new(Sid)

        signn = pkcs1_15.new(key)
        signature = signn.sign(hash)
        myPOSID.POS = signature.hex()


        jsonStr = json.dumps(my_CardSID.__dict__)
        res = bytes(jsonStr, 'utf-8')

        res = pad(res, BLOCK_SIZE)
        cipher = AES.new(aesKey, AES.MODE_ECB)
        ciphertext = cipher.encrypt(res)

        myPOSID.PM = ciphertext.hex()

        jsonStr = json.dumps(myPOSID.__dict__)
        res = bytes(jsonStr, 'utf-8')
        res = pad(res, BLOCK_SIZE)
        cipher = AES.new(aesKey, AES.MODE_ECB)
        ciphertext = cipher.encrypt(res)

        client_socket.send(ciphertext)

    client_socket.close()  # close the connection

client_program()