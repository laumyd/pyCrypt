import base64
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
import shutil
import argparse



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
    return(key)


def encrypt(file, key):
    
    try:
        fileName, fileEnd = file.split('.')
        os.mkdir(fileName)
        shutil.move(file, fileName)
        file = fileName
    except:
        pass

    shutil.make_archive(file, 'zip', file)
    # open File to encrypt
    with open(file + '.zip', 'rb') as f:
        data = f.read()

    fer = Fernet(key)
    encrypted = fer.encrypt(data)

    # write encrypted data
    file = file.replace('.zip', '')
    with open(file + '.pcrpt', 'wb') as f:
        f.write(encrypted)
    
    
    #shutil.rmtree(file)
    os.remove(file + '.zip')
    shutil.rmtree(file)



def decrypt(file, key):
    fileName, fileEnd = file.split('.')
    # open File to decrypt
    with open(file, 'rb') as f:
        data = f.read()

    Fer = Fernet(key)
    decrypted = Fer.decrypt(data)

    # write decrypted data
    with open(fileName + '.zip', 'wb') as f:
        f.write(decrypted)
        
    shutil.unpack_archive(fileName + '.zip', fileName)

    os.remove(fileName + '.zip')
    os.remove(fileName + '.pcrpt')
    


def run(args):
    if args.mode.casefold() in ('e', 'encrypt'):
        encrypt(args.input, encryption(args.password))
    if args.mode.casefold() in ('d', 'decrypt'):
        decrypt(args.input, encryption(args.password))

def main():
	parser=argparse.ArgumentParser(description="")
	parser.add_argument("-i, --input",help="input file", metavar='', dest="input", type=str, required=True)
	parser.add_argument("-p, --password",help="file password", metavar='', dest="password", type=str, required=True)
	parser.add_argument("-m, --mode", help="Encrypt or Decrypt", metavar='', dest="mode", type=str, required=True)
	parser.set_defaults(func=run)
	args=parser.parse_args()
	args.func(args)


if __name__=="__main__":
	main()








