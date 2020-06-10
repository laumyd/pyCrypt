import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import shutil



# Get key from Password
password_provided = input("Password: ") # set password
password = "a"

if (password == password_provided):
    password_Encoded = password.encode() # convert to bytes

    salt = b'\xb9~\xb5"\xb6\x03\xa9U^g\xc0\xdcb\xb8\xec\xb3'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_Encoded)) # can only use kdf once
    print (key)
else:
    print("Invalid Password")
    exit()



def encrypt(file):
    # open File to encrypt
    with open(file, 'rb') as f:
        data = f.read()

    fer = Fernet(key)
    encrypted = fer.encrypt(data)

    # write encrypted data
    file = file.replace('.zip', '')
    with open(file + '.encrypted', 'wb') as f:
        f.write(encrypted)
    

def decrypt(file):
    # open File to decrypt
    with open(file + '.encrypted', 'rb') as f:
        data = f.read()

    Fer = Fernet(key)
    decrypted = Fer.decrypt(data)

    # write decrypted data
    with open(file + '.zip', 'wb') as f:
        f.write(decrypted)
    
def zipCompile(file):
    shutil.make_archive(file, 'zip', file)
    
def zipEcstract(file):
    shutil.unpack_archive(file + '.zip', file)


file = input("FileName: ")
crypt = input("E for Encrypt, D for Decrypt [E/D]: ")
print(crypt)

# Encrypt
if(crypt == "E" or crypt == "e"):
    zipCompile(file)
    encrypt(file + '.zip')
    shutil.rmtree(file)
    os.remove(file + '.zip')
    

# Decrypt
if(crypt == "D" or crypt == "d"):
    decrypt(file)
    zipEcstract(file)

    os.remove(file + '.zip')
    os.remove(file + '.encrypted')






