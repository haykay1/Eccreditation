import os
from pathlib import Path
import os 

from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from hashing import Hashing as HS

class Randomness():
    def generate_key():#Function that generate key
        path = input('Please Enter the Path to save your Keys: ')#prompt message for where the key will be save
        key = RSA.generate(2048)#RSA method byte max
        os.makedirs(path, exist_ok=True)#Create directory
        privatekey = key.export_key()# Generate the key
        file_out = open(os.path.join(path,"private.pem"), "wb")#save the Private key
        file_out.write(privatekey)
        file_out.close()#close the method

        publickey = key.publickey().export_key()#generate public Key
        file_out = open(os.path.join(path,"public.pem"), "wb")
        file_out.write(publickey)
        file_out.close()#close the the file connection
#ecryption function: this function use the Encrypt the folder/file
    def encryption():
        Directory = input("Please enter the folder or path to be encrypted: ")
        dir_path = input('Please enter path to save your encrypted folder: ')
        receiver = input('Please enter the  public key file name with directory: ')
        os.makedirs(dir_path, exist_ok=True)
        assert Path(Directory).is_dir()
        for new_path in sorted(Path(Directory).iterdir(), key=lambda p: str(p).lower()):
            with open(new_path, 'rb') as p:
                new_file_name = os.path.basename(new_path)
                hash_has = HS(new_path)
                hash_has.hashing()

                encrypted_path_text = 'encrypted  ' + new_file_name                     
                recipient_key = RSA.import_key(open(receiver).read())
                AES_key_generate = get_random_bytes(32)

                rsa_cipher = PKCS1_OAEP.new(recipient_key) 
                enc_AES_key = rsa_cipher.encrypt(AES_key_generate)

                # original_message = open(p, 'rb')
                textFile = p.read()
                textFile = bytearray(textFile) 

                aes_cipher = AES.new(AES_key_generate, AES.MODE_EAX)
                ciphertext, tag = aes_cipher.encrypt_and_digest(textFile) # Encrypting thr file and generating the Cipher text and the hash digest(hash function)
                encrypted_path_object = open(os.path.join(dir_path,encrypted_path_text), 'wb') # opening the file just created 
                [ encrypted_path_object.write(x) for x in (enc_AES_key, aes_cipher.nonce, tag, ciphertext) ] # Storing our result in a file
                encrypted_path_object.close() 
                p.close()
        print('Encryption is complete, please check the directory specified') 
#decryption function: this function use the  keygenerated to decrypt the file/folder encrypted
    def decryption():
    
        Directory = input('Enter the encrypted folder or path: ')
        dir_path = input('Please enter path to save your decrypted folder: ')
        private = input('Enter the private key name or path : ')
        os.makedirs(dir_path, exist_ok=True)
        assert Path(Directory).is_dir()
        for new_path in sorted(Path(Directory).iterdir(), key=lambda p: str(p).lower()):
            with open(new_path, 'rb') as file_in:
                new_file_name = os.path.basename(new_path)   
                encrypted_file_text = 'decrypted ' + new_file_name
                encrypted_file_object = open(encrypted_file_text, 'wb')

                
                private_key = RSA.import_key(open(private).read())
                enc_AES_key,nonce, tag,ciphertext = \
                [file_in.read(x) for x in (private_key.size_in_bytes(),16,16,-1) ]

                # Decrypt the session key with the private RSA key
                cipher_rsa = PKCS1_OAEP.new(private_key)
                AES_key = cipher_rsa.decrypt(enc_AES_key)
                # Decrypt the data with the AES session key
                cipher_aes = AES.new(AES_key, AES.MODE_EAX, nonce)
                data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                encrypted_file_object.write(data)
                encrypted_file_object.close()  
                
    print('Decryption is complete, please check the directory specified') #this is a message output at the end of decryption process
