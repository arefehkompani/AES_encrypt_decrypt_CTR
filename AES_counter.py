import os
import pbkdf2
import binascii
import secrets
import pyaes

key = "AUT*ICTSec*2022"
keySalt = os.urandom(32)
ar = [key, keySalt]

with open('key.txt', 'w') as f:
    for line in ar:
        f.write("%s\n" % line)
f.close()

def UI():

    keyfile = readkey()
    keyWithSalt = keyfile.split('\n')
    key256 = pbkdf2.PBKDF2(keyWithSalt[0], keyWithSalt[1]).read(32)
    toHex = binascii.hexlify(key256)
    print('\nAlgorithm key is: ')
    print(toHex)
    print('\n')

    iv = secrets.randbits(256)

    
    # Encryption
    filePlain = open("plaintext.txt", "r")
    pt = filePlain.read()
    filePlain.close()

    aes1 = pyaes.AESModeOfOperationCTR(key256, pyaes.Counter(iv))
    ciphertext = aes1.encrypt(pt)
    print('Encrypted:', binascii.hexlify(ciphertext))
    print('------------------------------------------')

    fileCipher = open("ciphertext.txt", "w")
    fileCipher.write(str(binascii.hexlify(ciphertext)))
    fileCipher.close()
    
    # Decryption
    readCipher = open("ciphertext.txt", "r")
    ct = readCipher.read()
    readCipher.close()
    
    ct = ct.lstrip(ct[0:2])
    ct = ct[:len(ct)-1]
    ct = binascii.unhexlify(ct)

    aes2 = pyaes.AESModeOfOperationCTR(key256, pyaes.Counter(iv))
    decrypted = aes2.decrypt(ct)
    print("Decrypted: ")
    print(decrypted)
    print('---------------------------')
        
       

def readkey():
    readkeyf = open("key.txt", "r")
    readkey = readkeyf.read()
    readkeyf.close()
    
    return readkey
UI()