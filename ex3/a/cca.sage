from edwards25519 import Edwards25519
import os
from hashlib import sha256
import random
from operator import xor  

class EdwardsElGamal:
    def __init__(self, security_param=128):
        self.lambda_security = security_param
        self.curve = Edwards25519()  
        self.G = self.curve.create_point()  
        self.L, self.h = self.curve.order()  
    
    def keygen(self):
        s = random.randint(1, int(self.L) - 1)
        H_point = self.G.mult(s) 
        return (H_point, s)
    
    def H(self, value, length=32):
        if isinstance(value, (int, Integer)):
            value_str = str(value)
        elif isinstance(value, tuple):
            value_str = f"{value[0]}:{value[1]}"
        else:
            value_str = str(value)
            
        return int.from_bytes(sha256(value_str.encode()).digest(), byteorder='big') % (2**length)
    
    
    def encrypt_message(self, public_key, plaintext):
        
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
        
        m_int = int.from_bytes(plaintext_bytes, byteorder='big')
        
        # FO -> 1
        r = random.randint(1, 2**128 - 1) #teve que ser assim por causa do tamanho...
        print(f"Generated r : {r}")
        
        Gamma = self.G.mult(r) 
        
        pk = public_key 
        S = pk.mult(r) 
        
        shared_key = sha256(f"{int(S.x)}:{int(S.y)}".encode()).digest() 
        shared_key_int = int.from_bytes(shared_key[:16], byteorder='big')
        if shared_key_int % 2 == 0:
            shared_key_int += 1
            
        # FO -> 2
        combined_data = (r << 128) + m_int
        
        # FO -> 3
        ciphertext_int = (combined_data * shared_key_int) % (2**256)
        ciphertext = ciphertext_int.to_bytes(32, byteorder='big')

        # FO -> 4
        r_hash = self.H(r)
        
        return ((int(Gamma.x), int(Gamma.y)), ciphertext, r_hash)
    
    def decrypt_message(self, private_key, encrypted_data):

        (gamma_x, gamma_y), ciphertext, r_hash = encrypted_data
        
        Gamma = self.curve.create_point(self.curve.K(gamma_x), self.curve.K(gamma_y))
        
        S = Gamma.mult(private_key)
        
        shared_key = sha256(f"{int(S.x)}:{int(S.y)}".encode()).digest()
    
        ciphertext_int = int.from_bytes(ciphertext, byteorder='big')
        
        shared_key_int = int.from_bytes(shared_key[:16], byteorder='big')
        if shared_key_int % 2 == 0:
            shared_key_int += 1
        shared_key_inv = pow(shared_key_int, -1, 2**256)
        
        combined_data = (ciphertext_int * shared_key_inv) % (2**256)
        
        r = combined_data >> 128
        print(f"Decrypted r : {r}")
        m_int = combined_data & ((1 << 128) - 1)
        
        r_hash_rec = self.H(r)
        print(f"Hash of received r : {r_hash_rec}")
        gamma_rec = self.G.mult(r)
        gamma_check = gamma_rec.x == Gamma.x and gamma_rec.y == Gamma.y
        
        if r_hash != r_hash_rec or not gamma_check:
            raise ValueError("Invalid ciphertext")
        
        
        byte_length = max(1, (m_int.bit_length() + 7) // 8)
        m_bytes = m_int.to_bytes(byte_length, byteorder='big')
        plaintext = m_bytes.decode('utf-8') 
        
        return plaintext

if __name__ == "__main__":
    elgamal = EdwardsElGamal(security_param=128)
    
    public_key, private_key = elgamal.keygen()
    
    plaintext = "Hello World!"
    
    print("=" * 40)
    print(f"Mensagem original: {plaintext}")
    
    encrypted_data = elgamal.encrypt_message(public_key, plaintext)
    gamma, ciphertext, r_hash = encrypted_data
    gamma_x, gamma_y = gamma
    
    print("=" * 40)
    print("==== DADOS CIFRADOS ====")
    print(f"Gamma (ponto na curva):")
    print(f"  x: {gamma_x}")
    print(f"  y: {gamma_y}")
    print(f"\nCiphertext (em hexadecimal): {ciphertext.hex()}")
    print(f"\nHash de r :{r_hash}")
    print("=" * 40)

    decrypted = elgamal.decrypt_message(private_key, encrypted_data)
    
    print(f"Mensagem decifrada: {decrypted}")
    print("=" * 40)
    print(f"Sucesso? {plaintext == decrypted}")
    print("=" * 40)
    