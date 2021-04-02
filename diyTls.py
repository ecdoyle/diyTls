# Prompt:
# Elliptic Curve Diffie-Hellman exchange to establish a shared secret.  Use a NIST approved curve. (Module 5)
# For each chunk of public information sent generate an RSA Digital Signature. (Module 6)
# Validate the RSA digital signature of the packets you receive. (Module 6)
# Once you have a shared key encrypt a message using AES in GCM mode (not in our notes but not too different). (Module 3)
# If you can pull that off (even as both sides of the conversation) then you'll have done a full industry ready HTTPS packet encryption.
# Here is an online site you can use to validate your ECDH parameters: http://www-cs-students.stanford.edu/~tjw/jsbn/ecdh.html

import json, binascii, os, random, rsa, hashlib
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
from Crypto.Util.number import *
from readparams import readParams

def gcm_en(msg, secretKey, iv):
    cipher = AES.new(secretKey, AES.MODE_GCM, iv)
    ct, authTag = cipher.encrypt_and_digest(msg)
    return (ct, authTag)

def gcm_de(encryptedMsg, secretKey, iv):
    (ct, authTag) = encryptedMsg
    cipher = AES.new(secretKey, AES.MODE_GCM, iv)
    pt = cipher.decrypt_and_verify(ct, authTag)
    return pt

def readFile(file):
    f = open(file, 'r')
    lngstr = f.read()
    f.close()
    return lngstr

def loadPrivateKeyFromFile(file):
    stg = readFile(file)
    key = rsa.PrivateKey.load_pkcs1(stg)
    return key

def loadPublicKeyFromFile(file):
    stg = readFile(file)
    key = rsa.PublicKey.load_pkcs1(stg.encode('ascii'))
    return key

def signInt(intg, key):
    return pow(intg, key.d, key.n)

def checkSignedBytes(bytez, key):
    return pow(bytez, key.e, key.n)

def verifySignedBytes(bytez, key, pt_as_int):
    ver = checkSignedBytes(bytez, key)
    return ver == pt_as_int

def signAndVerify(itemToSign, aPrivRsa, aPubRsa):
    # a sign's 
    signedVal = signInt(itemToSign, aPrivRsa)

    # pass to b and verify
    ver = verifySignedBytes(signedVal , aPubRsa, itemToSign)
    return ver

def sha256Str(strg):
    return hashlib.sha256(strg.encode('utf-8')).hexdigest()

def getPrivEcdh(key):
    return key.get('priv')

def getPubEcdh(key):
    return [key.get('priv')  * key.get('Gener')[0],key.get('priv')  * key.get('Gener')[1]] 

def getKeyValsEcdh(key):
    return getPrivEcdh(key), getPubEcdh(key)

def getSharedSecretEcdh(aPriv, bPub):
    return [aPriv * bPub[0], aPriv * bPub[1]]

def splitSharedSecretAndHash(secret):
    return binascii.unhexlify(sha256Str(str(secret[0]))), binascii.unhexlify(sha256Str(str(secret[1])))

### RSA generation
# Used: ssh-keygen -t rsa
aRsa = loadPrivateKeyFromFile('alice_rsa')
bRsa = loadPrivateKeyFromFile('bob_rsa')

# Used: ssh-keygen -f alice_rsa.pub -e -m pem > alice_rsa_pub
aRsa_pub = loadPublicKeyFromFile('alice_rsa_pub')
bRsa_pub = loadPublicKeyFromFile('bob_rsa_pub')

# Assuming that the public RSA keys are published and Alice grabs Bob's key and visa versa

### ECDHE 
# Generating Keys Commands:
# openssl ecparam -genkey -name secp160r1 -noout -param_enc explicit -out alice_private.pem
# openssl ec -in alice_private.pem -pubout -out alice_public.pem
# openssl ec -in alice_private.pem -noout -text > alice_private_parameters

# Read in ECDH values
aEcdh = readParams('alice_private_parameters')
aPrivEcdh, aPubEcdh = getKeyValsEcdh(aEcdh)
bEcdh = readParams('bob_private_parameters')
bPrivEcdh, bPubEcdh = getKeyValsEcdh(bEcdh)

# Signed Exchange for ECDH
aRx_bPub = [] # storage for a rxing b's public values
bRx_aPub = [] # storage for b rxing a's public values

# Alice's public ECDH
for val in aPubEcdh:
    ver = signAndVerify(val, aRsa, aRsa_pub)
    if ver:
        bRx_aPub.append(val)
    else:
        print("Alice's signature did not verify for val: ", val, " ,and signature: ", signedVal)

# Bob's public ECDH
for val in bPubEcdh:
    ver = signAndVerify(val, bRsa, bRsa_pub)
    if ver:
        aRx_bPub.append(val)
    else:
        print("Bob's signature did not verify for val: ", val, " ,and signature: ", signedVal)

# Omniscient sanity check #1
#print(bRx_aPub == aPubEcdh)
#print(aRx_bPub == bPubEcdh)

# get shared secret now that public ECDH have been exchanged and verified
aSharedEcdh = getSharedSecretEcdh(aPrivEcdh, aRx_bPub)
bSharedEcdh = getSharedSecretEcdh(bPrivEcdh, bRx_aPub)

# Omniscient sanity check #2
#print( aSharedEcdh == bSharedEcdh)

# Hash it so usable in AES GCM
aSharedEcdh_key, aSharedEcdh_iv = splitSharedSecretAndHash(aSharedEcdh)
bSharedEcdh_key, bSharedEcdh_iv = splitSharedSecretAndHash(bSharedEcdh)

### AES GCM Party
bobOutput=""
with open('textToSend.txt') as inputFile:
    for line in inputFile:
        # Alice encrypt
        encryptedMsg = gcm_en(str.encode(line), aSharedEcdh_key, aSharedEcdh_iv)
       
        # Alice Sign
        sigMsg = signInt(bytes_to_long(encryptedMsg[0]), aRsa)
        sigAuth = signInt(bytes_to_long(encryptedMsg[1]), aRsa)

        # Send to Bob & check signatures
        verMsg = verifySignedBytes(sigMsg, aRsa_pub , bytes_to_long(encryptedMsg[0]))
        verAuth = verifySignedBytes(sigAuth, aRsa_pub , bytes_to_long(encryptedMsg[1]))

        # If signatures are good, Bob decrypts
        if verMsg and verAuth:
            decryptedMsg = gcm_de(encryptedMsg, bSharedEcdh_key, bSharedEcdh_iv)
            bobOutput += decryptedMsg.decode("utf-8")
        else:
            print("signature did not check out :(")
    inputFile.close()

print("Decrypted output: ", bobOutput)

# Omniscient sanity check #3
with open('textToSend.txt') as inputFile:
    ogText = inputFile.read()
    inputFile.close()
print("Original text matches output? :", ogText == bobOutput)