
import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import shutil


###################################################################


password = input("password: ")
file = input("FileName: ")
crypt = input("E for Encrypt, D for Decrypt [E/D]: ")


###################################################################

def encryption(password):
    # get key from Password
    password = password.encode() # convert to bytes

    salt = b'\xb9~\xb5"\xb6\x03\xa9U^g\xc0\xdcb\xb8\xec\xb3'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password)) # can only use kdf once
    print (key)
    return(key)

#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

def zipCompile(file):
    shutil.make_archive(file, 'zip', file)
    
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

def zipEcstract(file):
    shutil.unpack_archive(file + '.zip', file)

#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#

def encrypt(file, key):
    
    zipCompile(file)
    # open File to encrypt
    with open(file + '.zip', 'rb') as f:
        data = f.read()

    fer = Fernet(key)
    encrypted = fer.encrypt(data)

    # write encrypted data
    file = file.replace('.zip', '')
    with open(file + '.encrypted', 'wb') as f:
        f.write(encrypted)
    
    
    shutil.rmtree(file)
    os.remove(file + '.zip')
    
#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#-#    

def decrypt(file, key):
    # open File to decrypt
    with open(file + '.encrypted', 'rb') as f:
        data = f.read()

    Fer = Fernet(key)
    decrypted = Fer.decrypt(data)

    # write decrypted data
    with open(file + '.zip', 'wb') as f:
        f.write(decrypted)
    
    zipEcstract(file)

    os.remove(file + '.zip')
    os.remove(file + '.encrypted')
    

############################################################



# Encrypt
if(crypt == "E" or crypt == "e"):
    encrypt(file, encryption(password))
    
# Decrypt
if(crypt == "D" or crypt == "d"):
    decrypt(file, encryption(password))
    







