
class Randomness():
    def generate_key():#Function that generate key

        
    def encryption():
        Directory = input()
        dir_path = input()
        receiver = input()
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

               
                textFile = p.read()
                textFile = bytearray(textFile) 

                aes_cipher = AES.new(AES_key_generate, AES.MODE_EAX)
                ciphertext, tag = aes_cipher.encrypt_and_digest(textFile)
                encrypted_path_object = open(os.path.join(dir_path,encrypted_path_text), 'wb') 
                [ encrypted_path_object.write(x) for x in (enc_AES_key, aes_cipher.nonce, tag, ciphertext) ] 
                encrypted_path_object.close() 
                p.close()
        print('Encryption is complete, please check the directory specified') 
    def decryption():
    
        Directory = input()
        dir_path = input()
        private = input()
        os.makedirs(dir_path, exist_ok=True)
        assert Path(Directory).is_dir()
        for new_path in sorted(Path(Directory).iterdir(), key=lambda p: str(p).lower()):
            with open(new_path, 'rb') as file_in:
                new_file_name = os.path.basename(new_path)   
                encrypted_file_text = 'decrypted ' + new_file_name
                encrypted_file_object = open(encrypted_file_text, 'wb')

                
                private_key = RSA.import_key(open(private).read())
                enc_AES_key,nonce, tag,ciphertext =
                [file_in.read(x) for x in (private_key.size_in_bytes(),16,16,-1) ]

                
                cipher_rsa = PKCS1_OAEP.new(private_key)
                AES_key = cipher_rsa.decrypt(enc_AES_key)
                # Decrypt the data with the AES session key
                cipher_aes = AES.new(AES_key, AES.MODE_EAX, nonce)
                data = cipher_aes.decrypt_and_verify(ciphertext, tag)
                encrypted_file_object.write(data)
                encrypted_file_object.close()  
                
    print('Decryption is complete, please check the directory specified')
