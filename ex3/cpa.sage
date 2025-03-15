from edwards25519 import Edwards25519
import os
from hashlib import sha256
import random
from operator import xor  # Importando a função xor do módulo operator

class EdwardsElGamal:
    """
    Implementação do ElGamal usando a curva Edwards25519
    """
    
    def __init__(self, security_param=128):
        """
        ElGamal em curvas de Edwards 
        """
        self.lambda_security = security_param
        self.curve = Edwards25519()  
        
        """
        Geramos o gerador , calculamos a ordem do grupo e o cofator
        """
        self.G = self.curve.create_point()  
        self.L, self.h = self.curve.order()  
    
    def keygen(self):
        """
        Gera um par de chaves (privada,pública) para ElGamal a partir do gerador G
        """

        s = random.randint(1, int(self.L) - 1)
        
        H_point = self.G.mult(s)  #(multiplicação escalar)
        
        return (H_point, s)
    
    def encrypt_message(self, public_key, plaintext):
        
        """
        Cifra uma mensagem usando ElGamal em curvas de Edwards  
        """
        
        omega = random.randint(1, int(self.L) - 1) # omega entre 1 e L-1, L sendo a ordem do grupo
        
        Gamma = self.G.mult(omega) # gamma = G·omega (multiplicação escalar), vai ser enviado ao receiver para poder decifrar
        
        pk = public_key 
        S = pk.mult(omega) # secret ->  S = ω·H (é um ponto secreto que vai servir para calcular a chave)
        
        shared_key = sha256(f"{int(S.x)}:{int(S.y)}".encode()).digest() # chave que vai ser usada para cifrar
        
        nonce = os.urandom(16) #precisamos disto para ser CPA, assim a cifra não é deterministica
        
        plaintext_bytes = plaintext.encode('utf-8')
        
        key_stream = sha256(shared_key + nonce).digest()
        while len(key_stream) < len(plaintext_bytes):
            key_stream += sha256(key_stream).digest()
            
        ciphertext = bytes(xor(a, b) for a, b in zip(plaintext_bytes, key_stream[:len(plaintext_bytes)]))
        
        return ((int(Gamma.x), int(Gamma.y)), ciphertext, nonce)
    
    def decrypt_message(self, private_key, encrypted_data):

        (gamma_x, gamma_y), ciphertext, nonce = encrypted_data
        
        Gamma = self.curve.create_point(self.curve.K(gamma_x), self.curve.K(gamma_y))
        
        S = Gamma.mult(private_key)
        
        shared_key = sha256(f"{int(S.x)}:{int(S.y)}".encode()).digest()
        
        key_stream = sha256(shared_key + nonce).digest()

        while len(key_stream) < len(ciphertext):
            key_stream += sha256(key_stream).digest()
        

        plaintext_bytes = bytes(xor(a, b) for a, b in zip(ciphertext, key_stream[:len(ciphertext)]))

        return plaintext_bytes.decode('utf-8')


if __name__ == "__main__":
    elgamal = EdwardsElGamal(security_param=128)
    
    public_key, private_key = elgamal.keygen()
    
    plaintext = "Hello World!"
    
    print(f"Mensagem original: {plaintext}")
    
    encrypted_data = elgamal.encrypt_message(public_key, plaintext)
    
    print(f"Mensagem cifrada: {encrypted_data}")

    decrypted = elgamal.decrypt_message(private_key, encrypted_data)
    
    print(f"Mensagem decifrada: {decrypted}")
    
    print(f"Sucesso? {plaintext == decrypted}")