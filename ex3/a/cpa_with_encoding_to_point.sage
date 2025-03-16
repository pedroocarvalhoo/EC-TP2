from edwards25519 import Edwards25519
import os
from hashlib import sha256
import random
from operator import xor  


class EdwardsElGamal:
    """
    Implementação do ElGamal usando a curva Edwards25519 com codificação de Koblitz
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
        H_point = self.G.mult(s)
        
        return (H_point, s)
    
    def try_and_increment(self, message_int, l=8):
        """
        Implementação do método "try-and-increment" para mapear mensagens a pontos
        
        Args:
            message_int: inteiro representando a mensagem
            l: parâmetro de segurança (bits para tentativas)
            
        Returns:
            EdPoint: ponto na curva Edwards que representa a mensagem
        """
        # Obter os parâmetros da curva
        p = self.curve.p
        a = self.curve.a
        d = self.curve.d
        K = self.curve.K
        
        # Tentar diferentes valores até encontrar um ponto válido
        for i in range(2**l):
            # Concatenar a mensagem com bits de padding
            x_int = (message_int << l) | i
            
            # Converter para elemento do campo
            x = K(x_int)
            
            # Para a curva Edwards com equação ax² + y² = 1 + dx²y²
            # Precisamos resolver para y²: y² = (1 - ax²)/(1 - dx²)
            
            # Verificar se o denominador é não-zero
            denominator = 1 - d * x**2
            if denominator == 0:
                continue
                
            # Calcular o numerador
            numerator = 1 - a * x**2
            
            # Calcular y²
            y_squared = numerator / denominator
            
            # Verificar se y_squared é um resíduo quadrático (tem raiz quadrada)
            # Usando o critério de Euler: a^((p-1)/2) ≡ 1 (mod p) para resíduos quadráticos
            if pow(y_squared, (p-1)//2, p) == 1:
                # Calcular a raiz quadrada
                # Para p ≡ 3 (mod 4), a raiz é a^((p+1)/4) mod p
                if p % 4 == 3:
                    y_int = pow(y_squared, (p+1)//4, p)
                else:
                    # Usar o algoritmo de Tonelli-Shanks para p ≡ 1 (mod 4)
                    y_int = self.tonelli_shanks(y_squared, p)
                
                y = K(y_int)
                
                # Verificar se o ponto está na curva
                point = self.curve.create_point(x, y)
                
                # Armazenar o valor i usado (para decodificação)
                point.encoding_index = i
                point.message_int = message_int
                
                return point
                
        # Se todas as tentativas falharem
        raise ValueError(f"Não foi possível codificar a mensagem após 2^{l} tentativas")
        
    def tonelli_shanks(self, n, p):
        """
        Implementação do algoritmo de Tonelli-Shanks para calcular raízes quadradas modulares
        Para casos em que p ≡ 1 (mod 4)
        
        Args:
            n: número do qual queremos a raiz quadrada
            p: módulo primo
            
        Returns:
            int: raiz quadrada de n módulo p
        """
        # Caso trivial
        if n == 0:
            return 0
            
        # Verificar se n é realmente um resíduo quadrático
        if pow(n, (p-1)//2, p) != 1:
            raise ValueError(f"{n} não é um resíduo quadrático módulo {p}")
            
        # Fatorar p-1 como Q * 2^S onde Q é ímpar
        Q, S = p - 1, 0
        while Q % 2 == 0:
            Q //= 2
            S += 1
            
        # Encontrar um não-resíduo quadrático z
        z = 2
        while pow(z, (p-1)//2, p) != p - 1:
            z += 1
            
        # Inicializar variáveis
        M = S
        c = pow(z, Q, p)
        t = pow(n, Q, p)
        R = pow(n, (Q+1)//2, p)
        
        # Loop principal do algoritmo
        while t != 1:
            # Encontrar o menor i tal que t^(2^i) ≡ 1 (mod p)
            i = 0
            temp = t
            while temp != 1 and i < M:
                temp = (temp * temp) % p
                i += 1
                
            if i == 0:
                return R
                
            # Calcular b = c^(2^(M-i-1)) mod p
            b = pow(c, 2**(M-i-1), p)
            
            # Atualizar variáveis
            M = i
            c = (b * b) % p
            t = (t * b * b) % p
            R = (R * b) % p
            
        return R
    
    def encode_message_to_point(self, message, l=8):
        """
        Codifica uma mensagem como um ponto na curva Edwards
        
        Args:
            message: Mensagem a ser codificada (string ou bytes)
            l: Parâmetro de segurança (bits para tentativas)
            
        Returns:
            EdPoint: Ponto na curva representando a mensagem
        """
        # Converter para bytes se for string
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        elif isinstance(message, bytes):
            message_bytes = message
        else:
            raise ValueError("A mensagem deve ser string ou bytes")
            
        # Converter para inteiro
        message_int = int.from_bytes(message_bytes, byteorder='big')
        
        # Adicionar o comprimento da mensagem como prefixo para decodificação correta
        length_prefix = len(message_bytes)
        full_message = (length_prefix << (8 * len(message_bytes))) | message_int
        
        # Usar o método try-and-increment para encontrar um ponto válido
        return self.try_and_increment(full_message, l)
    
    def decode_message_from_point(self, point):
        """
        Decodifica uma mensagem a partir de um ponto na curva
        
        Args:
            point: Ponto EdPoint que representa uma mensagem codificada
            
        Returns:
            bytes: Mensagem original
        """
        # Extrair o inteiro da coordenada x
        x_int = int(point.x)
        
        # Remover os bits de padding (guardados durante a codificação)
        if hasattr(point, 'encoding_index') and hasattr(point, 'message_int'):
            # Usar os valores armazenados (método mais confiável)
            message_with_length = point.message_int
        else:
            # Tentar recuperar a partir da coordenada x (menos confiável)
            # Assumir que os últimos 8 bits foram usados para padding
            message_with_length = x_int >> 8
        
        # Extrair o comprimento da mensagem (primeiros bytes)
        msg_length = message_with_length >> (8 * (message_with_length.bit_length() // 8))
        
        # Extrair a mensagem real
        message_int = message_with_length & ((1 << (8 * msg_length)) - 1)
        
        # Converter para bytes com o comprimento original
        return message_int.to_bytes(msg_length, byteorder='big')
    
    def encrypt_message(self, public_key, plaintext):
        """
        Cifra uma mensagem usando ElGamal em curvas de Edwards com codificação direta da mensagem
        
        Args:
            public_key: Chave pública (ponto na curva)
            plaintext: Mensagem em texto plano
            
        Returns:
            tuple: (C1, C2) onde C1 e C2 são pontos na curva
        """
        # Converter a mensagem para um ponto na curva
        M = self.encode_message_to_point(plaintext)
        
        # Gerar um escalar aleatório r
        r = random.randint(1, int(self.L) - 1)
        
        # Calcular C1 = r·G
        C1 = self.G.mult(r)
        
        # Calcular S = r·H (onde H é a chave pública)
        S = public_key.mult(r)
        
        # Calcular C2 = M + S
        C2 = M.add(S)
        
        return (C1, C2)
    
    def decrypt_message(self, private_key, encrypted_data):
        """
        Decifra uma mensagem usando ElGamal em curvas de Edwards com codificação direta da mensagem
        
        Args:
            private_key: Chave privada (escalar)
            encrypted_data: Tupla (C1, C2) de pontos na curva
            
        Returns:
            str ou bytes: Mensagem decifrada
        """
        C1, C2 = encrypted_data
        
        # Calcular S = s·C1 (onde s é a chave privada)
        S = C1.mult(private_key)
        
        # Calcular M = C2 - S = C2 + (-S)
        S_inv = S.sim()  # Inverso/negativo de S
        M = C2.add(S_inv)
        
        # Decodificar a mensagem a partir do ponto M
        message_bytes = self.decode_message_from_point(M)
        
        try:
            # Tentar decodificar como UTF-8
            return message_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # Retornar como bytes se não for UTF-8 válido
            return message_bytes

# Exemplo de uso:
if __name__ == "__main__":
    # Inicializar o esquema ElGamal em Edwards25519
    elgamal = EdwardsElGamal(security_param=128)
    
    # Gerar um par de chaves
    public_key, private_key = elgamal.keygen()
    
    # Mensagem para cifrar
    plaintext = "Hello!"
    
    print(f"Mensagem original: {plaintext}")
    
    # Cifrar a mensagem
    encrypted_data = elgamal.encrypt_message(public_key, plaintext)
    
    print(f"Mensagem cifrada: {encrypted_data}")
    
    # Decifrar a mensagem
    decrypted = elgamal.decrypt_message(private_key, encrypted_data)
    
    print(f"Mensagem decifrada: {decrypted}")
    
    # Verificar se a decifração foi bem-sucedida
    print(f"Decifração correta: {plaintext == decrypted}")