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
        Inicializa o esquema ElGamal em curvas de Edwards
        
        Args:
            security_param: parâmetro de segurança lambda
        """
        self.lambda_security = security_param
        self.curve = Edwards25519()  # Inicializa a curva Edwards25519
        
        # O gerador G é o ponto base da curva
        self.G = self.curve.create_point()  # Usa o ponto gerador padrão da curva
        
        # Obtém a ordem do grupo
        self.L, self.h = self.curve.order()  # L é a ordem do subgrupo, h é o cofator
    
    def keygen(self):
        """
        Gera um par de chaves (pública, privada) para ElGamal
        
        Returns:
            tuple: (chave_publica, chave_privada)
        """
        # Gerar chave privada como um escalar aleatório
        # s deve ser um número entre 1 e L-1 (ordem do subgrupo)
        s = random.randint(1, int(self.L) - 1)
        
        # Calcular a chave pública H = s·G (multiplicação escalar)
        H_point = self.G.mult(s)  # Usa o método mult da classe EdPoint
        
        return (H_point, s)
    
    def encrypt_message(self, public_key, plaintext):
        """
        Cifra uma mensagem usando ElGamal em curvas de Edwards
        
        Args:
            public_key: chave pública (ponto na curva)
            plaintext: mensagem em texto plano
            
        Returns:
            tuple: ((Γ.x, Γ.y), texto_cifrado, nonce)
        """
        # Gerar um valor aleatório ω entre 1 e L-1
        omega = random.randint(1, int(self.L) - 1)
        
        # Calcular Γ = ω·G
        Gamma = self.G.mult(omega)
        
        # Calcular o segredo compartilhado S = ω·H (onde H é a chave pública)
        S = public_key.mult(omega)
        
        # Derivar uma chave simétrica do segredo compartilhado
        shared_key = sha256(f"{int(S.x)}:{int(S.y)}".encode()).digest()
        
        # Gerar um nonce aleatório para a cifra simétrica
        nonce = os.urandom(16)
        
        # Cifrar a mensagem com a chave simétrica e o nonce
        plaintext_bytes = plaintext.encode('utf-8')
        key_stream = sha256(shared_key + nonce).digest()
        
        # Garantir que o key_stream é tão longo quanto a mensagem
        while len(key_stream) < len(plaintext_bytes):
            key_stream += sha256(key_stream).digest()
        
        # Cifrar com XOR usando o método .__xor__() ou a função xor()
        # Opção 1: Usar a função xor() do módulo operator
        ciphertext = bytes(xor(a, b) for a, b in zip(plaintext_bytes, key_stream[:len(plaintext_bytes)]))
        
        # Opção 2: Chamar o método .__xor__() explicitamente
        # ciphertext = bytes(a.__xor__(b) for a, b in zip(plaintext_bytes, key_stream[:len(plaintext_bytes)]))
        
        # Retornar o ponto Γ, o texto cifrado e o nonce
        return ((int(Gamma.x), int(Gamma.y)), ciphertext, nonce)
    
    def decrypt_message(self, private_key, encrypted_data):
        """
        Decifra uma mensagem usando ElGamal em curvas de Edwards
        
        Args:
            private_key: chave privada (escalar)
            encrypted_data: tupla ((Γ.x, Γ.y), texto_cifrado, nonce)
            
        Returns:
            str: mensagem em texto plano
        """
        (gamma_x, gamma_y), ciphertext, nonce = encrypted_data
        
        # Reconstruir o ponto Γ
        Gamma = self.curve.create_point(self.curve.K(gamma_x), self.curve.K(gamma_y))
        
        # Calcular o segredo compartilhado S = s·Γ
        S = Gamma.mult(private_key)
        
        # Derivar a mesma chave simétrica
        shared_key = sha256(f"{int(S.x)}:{int(S.y)}".encode()).digest()
        
        # Gerar o mesmo key_stream
        key_stream = sha256(shared_key + nonce).digest()
        
        # Garantir que o key_stream é tão longo quanto o texto cifrado
        while len(key_stream) < len(ciphertext):
            key_stream += sha256(key_stream).digest()
        
        # Decifrar com XOR usando o método .__xor__() ou a função xor()
        # Opção 1: Usar a função xor() do módulo operator
        plaintext_bytes = bytes(xor(a, b) for a, b in zip(ciphertext, key_stream[:len(ciphertext)]))
        
        # Opção 2: Chamar o método .__xor__() explicitamente
        # plaintext_bytes = bytes(a.__xor__(b) for a, b in zip(ciphertext, key_stream[:len(ciphertext)]))
        
        # Converter de volta para texto
        return plaintext_bytes.decode('utf-8')


# Exemplo de uso:
if __name__ == "__main__":
    # Inicializar o esquema ElGamal em Edwards25519
    elgamal = EdwardsElGamal(security_param=128)
    
    # Gerar um par de chaves
    public_key, private_key = elgamal.keygen()
    
    # Mensagem para cifrar
    plaintext = "Hello, Edwards!"
    
    print(f"Mensagem original: {plaintext}")
    
    # Cifrar a mensagem
    encrypted_data = elgamal.encrypt_message(public_key, plaintext)
    
    print(f"Mensagem cifrada: {encrypted_data}")
    
    # Decifrar a mensagem
    decrypted = elgamal.decrypt_message(private_key, encrypted_data)
    
    print(f"Mensagem decifrada: {decrypted}")
    
    # Verificar se a decifração foi bem-sucedida
    print(f"Decifração correta: {plaintext == decrypted}")