

class Hashing:
    def __init__(self, filename):
        self.filename = filename
      
        self.BLOCK_SIZE = 6532538
    def hashing(self):
        new_file_name = os.path.basename(self.filename)
        file_hash = sha256() 
        with open(self.filename,'r',encoding='utf-8', errors='ignore') as f: 
            fb = f.read() 
            while len(fb) > 0: 
                file_hash.update(fb.encode('utf-8'))
                fb = f.read() 
     
        hash_file = "Hash_" + new_file_name
        hash_file_object = open(hash_file, 'w')
        hash_file_object.write(file_hash.hexdigest())
        hash_file_object.close()
