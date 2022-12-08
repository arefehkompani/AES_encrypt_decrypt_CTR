import os
import pbkdf2
import binascii
import secrets
import pyaes

key = "AUT*ICTSec*2022"
keySalt = os.urandom(32)
ar = [key, keySalt]

# Write key with salt
with open('key.txt', 'w') as f:
    for line in ar:
        f.write("%s\n" % line)
f.close()

def readkey():
    readkeyf = open("key.txt", "r")
    readkey = readkeyf.read()
    readkeyf.close()
    return readkey

keyfile = readkey()
keyWithSalt = keyfile.split('\n')
key256 = pbkdf2.PBKDF2(keyWithSalt[0], keyWithSalt[1]).read(32)
toHex = binascii.hexlify(key256)
print('\nAlgorithm key is: ')
print(toHex)
print('\n')

def UI():
    iv = secrets.randbits(256)

    print('Please choose one of the following options: \n1-Encryption \n2-Decryption\n')
    action = input()

    if action == '1' or action == 'E' :
        # Encryption
        filePlain = open("plaintext.txt", "r")
        pt = filePlain.read()
        filePlain.close()

        aes1 = pyaes.AESModeOfOperationCTR(key256)
        ciphertext = aes1.encrypt(pt)

        print('Encrypted:', binascii.hexlify(ciphertext))
        print('------------------------------------------')

        # Write ciphertext
        fileCipher = open("ciphertext.txt", "w")
        fileCipher.write(str(binascii.hexlify(ciphertext)))
        fileCipher.close()
        
        UI()

    elif action == '2' or action == 'D' :
        
        readCipher = open("ciphertext.txt", "r")
        ct = readCipher.read()
        readCipher.close()

        ct = ct.lstrip(ct[0:2])
        ct = ct[:len(ct)-1]
        ct = binascii.unhexlify(ct)
        
        aes3 = pyaes.AESModeOfOperationCTR(key256)
        decrypted = aes3.decrypt(ct)

        print("Decrypted: ")
        print(decrypted)
        print('------------------------------------------')

        UI()

    else:
        print('\nThe selected option is wrong. Please try again')
        UI()

UI()