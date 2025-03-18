# Imports
from sage.all import *
import secrets
from cryptography.hazmat.primitives import hashes

# Parametros para a curva edwards22519
p = 2^255-19
K = GF(p)
a = K(-1)
d = -K(121665)/K(121666)

ed25519 = {
    'b'  : 256,
    'Px' : K(15112221349535400772501151409588531511454012693041857206046113283949847762202),
    'Py' : K(46316835694926478169428394003475163141307993866256225615783033603165251855960),
    'L'  : ZZ(2^252 + 27742317777372353535851937790883648493), ## ordem do subgrupo primo
    'n'  : 254,
    'h'  : 8
}

##########################
# Parametros / setup
debug = False
##########################

# Classe de criação de curva de edwards/weiterstrass. 
# É necessario utilizar as curvas de weiterstrass porque o sagemath já as implementa, entao podemos utilizar para definir curvas de edwards assim.
class Ed(object):
    # Construtor da classe que prepara alguns parametros auxiliares
    def __init__(self, p, a, d, ed = None):
        # Garantir que 'a' e 'd' são diferentes, e que 'p' é um numero primo grande
        assert a != d and is_prime(p) and p > 3
        
        # Criar um corpo finito modulo p (permite realizar varias operações)
        K = GF(p) 
  
        # Valores que permitem mapear a curva de edwards para weiterstrass
        A =  2*(a + d)/(a - d)
        B =  4/(a - d)
        alfa = A/(3*B)  
        s = B

        # Coeficientes na curva de weiterstrass (y^2 = x^3 + a4 * x + a6)
        a4 = s^(-2) - 3*alfa^2
        a6 = -alfa^3 - a4*alfa
        
        # Parametros para a criação da curva 
        self.K = K # Guardar o corpo finito
        self.constants = {'a': a , 'd': d , 'A':A , 'B':B , 'alfa':alfa , 's':s , 'a4':a4 , 'a6':a6 }
        self.EC = EllipticCurve(K,[a4,a6]) # Criação da curva eliptica na forma de weiterstrass 
        
        # Se forem fornecidos parametros como input
        if ed != None:
            self.L = ed['L'] # Obter o L apartir do dicionario
            self.P = self.ed2ec(ed['Px'],ed['Py']) # Criar um gerador de pontos de weiterstrass apartir dos pontos de edwards fornecidos
        else:
            self.gen() # Gera aleatoriamente um ponto na curva que sirva de gerador
    
    # Devolve a ordem prima "n" do maior subgrupo da curva, e o respetivo cofator "h" 
    def order(self):
        oo = self.EC.order() # Numero total de pontos na curva
        n,_ = list(factor(oo))[-1] # Obter fatores
        return (n,oo//n) # Retorna o maior subgrupo primo e o cofator
    
    # Gera aleatoriamente um ponto na curva que sirva de gerador
    def gen(self):
        L, h = self.order()       
        P = O = self.EC(0)
        while L*P == O:
            P = self.EC.random_element()
        self.P = h*P ; self.L = L
  
    # Função que verifica se um ponto pertence á curva de edwards
    def is_edwards(self, x, y):
        a = self.constants['a'] # Obter o valor de a declarado (parametro da curva)
        d = self.constants['d'] # Obter o valor de d declarado (parametro da curva)
        x2 = x^2 # Calcular o valor de x ao quadrado  
        y2 = y^2 # Calculcar o valor de y ao quadrado
        return a*x2 + y2 == 1 + d*x2*y2 # Equação da curva de twisted edwards curves (a * x^2 + y^2 = 1 + d * x^2 * y^2)

    # Passa um ponto de curva de edwards para um ponto de curva de ec
    def ed2ec(self,x,y):      
        if (x,y) == (0,1):
            return self.EC(0)
        z = (1+y)/(1-y) 
        w = z/x
        alfa = self.constants['alfa']
        s = self.constants['s']
        return self.EC(z/s + alfa , w/s)
    
    # Passa um ponto de curva de ec para curva de edwards
    def ec2ed(self,P):    
        if P == self.EC(0):
            return (0,1)
        x,y = P.xy() # Obter o valor x e y
        alfa = self.constants['alfa']
        s = self.constants['s']
        u = s*(x - alfa)  
        v = s*y
        return (u/v , (u-1)/(u+1))
    
    # Points class of ED
class ed(object):
    def __init__(self,pt=None,curve=None,x=None,y=None):
        if pt != None:
            self.curve = pt.curve
            self.x = pt.x ; self.y = pt.y ; self.w = pt.w
        else:
            assert isinstance(curve,Ed) and curve.is_edwards(x,y)
            self.curve = curve
            self.x = x ; self.y = y ; self.w = x*y
    
    # Verifica se dois pontos são equivalentes
    def eq(self,other):
        return self.x == other.x and self.y == other.y
    
    # Devolve uma copia do ponto atual
    def copy(self):
        return ed(curve=self.curve, x=self.x, y=self.y)
    
    # Devolve o ponto zero
    def zero(self):
        return ed(curve=self.curve,x=0,y=1)
    
    # Devolve o ponto simetrico
    def sim(self):
        return ed(curve=self.curve, x= -self.x, y= self.y)

    # Soma de dois pontos    
    def soma(self, other):
        a = self.curve.constants['a']; d = self.curve.constants['d']
        delta = d*self.w*other.w
        self.x, self.y  = (self.x*other.y + self.y*other.x)/(1+delta), (self.y*other.y - a*self.x*other.x)/(1-delta)
        self.w = self.x*self.y
        
    # Duplicação de um ponto
    def duplica(self):
        a = self.curve.constants['a']; d = self.curve.constants['d']
        delta = d*(self.w)^2
        self.x, self.y = (2*self.w)/(1+delta) , (self.y^2 - a*self.x^2)/(1 - delta)
        self.w = self.x*self.y
        
    # Multiplicação de um ponto por um escalar
    def mult(self, n):
        m = Mod(n,self.curve.L).lift().digits(2)   ## obter a representação binária do argumento "n"
        Q = self.copy() ; A = self.zero()
        for b in m:
            if b == 1:
                A.soma(Q)
            Q.duplica()
        return A
    
    # Encoding para representar um ponto para bytes
def encode_points(x, y):
    # Verificar se os pontos pertecem a uma curva de edwards
    E = Ed(p, a, d, ed25519) # Criar instancia do edwards
    if not E.is_edwards(x, y):
        raise ValueError("O ponto (x, y) não pertence à curva Edwards definida.")

    # Converter os pontos para inteiros
    x_int = int(x) # Passar o valor x para int
    y_int = int(y) # Passar o valor y para int

    # --------------------------
    # Passo 1: "Encode the y-coordinate as a little-endian string of 32 octets"
    y_bytes = y_int.to_bytes(32, byteorder='little')

    # --------------------------
    # Passo 2: "Copy the least significant bit of the x-coordinate to the most significant bit of the final octet"
    sign_bit = x_int & 1  # Extrair o ultimo bit do x

    # Copiar o LSB de x para o MSB do último octeto de y
    y_byteArray = bytearray(y_bytes)
        
    if sign_bit == 1:
        y_byteArray[31] |= 0x80  # Define o MSB para 1 (0x80 = 10000000 em binário)
    else:
        y_byteArray[31] &= 0x7F  # Garante que o MSB seja 0 (0x7F = 01111111 em binário)

    result = bytes(y_byteArray)

    # --------------------------
    # Modo debug
    if(debug):
        print("[ENCODE] Recebido x: " + str(x))
        print("[ENCODE] Recebido y: " + str(y))
        print("[ENCODE] Output: " + str(result))

    return result

# Função auxiliar do decoder de pontos que permite obter a raiz modulo (x^2 = n mod p)
# Irei seguir o (NIST SP 800-186, Appendix E).
def tonelliShanks(x2, p):
    n = x2

    # 1 passo: "Find q and s (with q odd), such that p–1 = q * 2^s"
    # Vamos iterar o q e o s até que nao seja possivel simplificar mais a equação 
    Q = p - 1 # Inicializar o q com valor igual a p-1, ou seja se o s for 0
    S = 0    

    # 2 passo: Aplicar verificar se o Q ainda é divisivel por 2, se for então é possivel aumentar o s em 1 denovo
    while Q % 2 == 0:
        Q = Q // 2 # Dividir o q por 1 pois o valor de 2 vai passar a ser representado por um incremento no S (// é divisão inteira)
        S += 1 

    # 3 passo: "Check to see if nq = 1"
    t = pow(n, Q, p)  # n^q mod p
    if t == 1:
        # "If so, then the root x = n(q+1)/2 mod p"
        return pow(n, (Q+1)//2, p) # Solução imediata se existir
    
    # Prosseguir a escolher z e entrando no loop principal
    else:
        # 4 passo: "Select a z, which is a quadratic non-residue modulo p"
        # Nota: "The Legendre symbol (a/p) where p is an odd prime and prime and a is an integer, can be used to test candidate values for z to see if a value of –1 is returned"
        found_candidate = 0
        for candidate in range(2, p):
            # Usando a identidade de euler (z/p) == z^(p-1/2)
            ls = pow(candidate, (p - 1) // 2, p)
            if ls == p - 1:  # pois p-1 ≡ -1 (mod p)
                found_candidate = candidate
                break
        
        # Se nao existir candidato para Z matar tudo
        if found_candidate == 0:
            raise ValueError("[TONELLI-SHANKS] Não foi encontrado QNR")
        
        # Passo 5: Inicialização dos valores para o loop
        z = found_candidate
        c = pow(z, Q, p) # "Set c = zq mod p. " 
        t = pow(n, Q, p) # "Set t = nq mod p.""
        R = pow(n, (Q + 1)//2, p) # "Set x = n(q+1)/2 mod p."
        M = S # "Set m = s"

        # Passo 6: "While t != 1"
        while t != 1:
            # Passo 7: "Find the smallest i, such that 𝑡^2^i = 1"
            t2i = t # Definir valor auxiliar incial

            # Iterar todos os valores de i até que t^2^i = 1
            i = 0
            for i in range(1, M): # Esta definido que "0 < i < m"
                t2i = pow(t2i, 2, p)
                if t2i == 1:
                    break # Foi encontrado um i que torna isto valido
            
            # Situação rara de erro
            if i == M:
                raise ValueError("[TONELLI-SHANKS] Não foi encontrado um valor valido de i")
            
            # Atualizar os valores
            b = pow(c, 1 << (M - i - 1), p) 
            R = (R * b) % p
            t = (t * b * b) % p
            c = pow(b, 2, p)
            M = i

        return R
    
    # Faz decode de uma string de bytes para um ponto y e x (encoded: pontos_da_curva, d:coeficiente_curva, p:numero_primo_corpo)
def decode_points(encoded, d, p):
    ####################################### PRIMEIRA PARTE (Obter o valor x0 e o valor y) ####################################### 
    # 1 Passo: "Interpret the octet string as an integer in little-endian representation"
    enc_val = int.from_bytes(encoded, byteorder="little")

    # 2 Passo: "The most significant bit of this integer is the least significant bit of the x-coordinate"
    x0 = (enc_val >> 255) & 1 # Damos shift do bit que queremos para a ultima posição e extraimos com o &1

    # 3 Passo: "The ycoordinate is recovered simply by clearing this bit"
    y_val = enc_val & ((1 << 255) - 1) # Criar sequencia de bits "valor & (...)111111110" que irá colocar o msb a 0

    # 4 Passo: "If the resulting value is ≥ p, decoding fails"
    if y_val >= p:
        raise ValueError("Decodificação falhou: y_val >= p.")

    ####################################### SEGUNDA PARTE (Obter o valor x2) #######################################
    # Ao pegar na equação da curva de edwards é possivel reorganiza-la para ficar ordem x^2
    # x^2 = (y^2 - 1) / (d y^2 - a) (mod p). O objetivo será calcular o x^2. 

    # 1 Passo: Calcular y^2 (Mod p porque toda a aritmetica é feita mod p em corpos finitos)
    y2 = pow(y_val, 2, p)

    # 2 Passo: Calcular o numerador e denominador
    N = (y2 - 1) % p      # Numerador = y^2 - 1
    D = (d * y2 + 1) % p  # D = d * y^2 + 1

    # 3 Passo: Verificar se o denominador dá 0
    if D == 0:
        raise ValueError("Decodificação falhou: denominador zero na equação")
    
    # Esta equação simplifica a primeira equação: x^2 ≡ N * D^−1 (mod p)
    # Vamos tentar obter o x2 utilizando o N e o D. Não é possivel dividir um numero por outro em aritmetica modular.
    # Entao teremos de utilizar multiplicação

    # Passo 3: Obter o inverso de D (Aplicando teorema de Fermat)
    D_inv = pow(D, p-2, p)

    # Passo 4: Aplicar a equação para obter o valor de x^2
    x2 = (N * D_inv) % p

    ####################################### TERCEIRA PARTE (Obter o valor de x) #######################################
    # Para obter o valor de x2 teremos de utilizar a formula de Tonelli-Shanks, que permite obter raiz quadrada modulo 
    # Irei seguir o (NIST SP 800-186, Appendix E).
    # Passo 5: Obter o x
    x_val = tonelliShanks(x2,p)
    
    # Verificar a paridade do x
    if (int(x_val) & 1) != x0:
        x_val = p - x_val # Se a paridade for diferente, então inverter o valor de x

    # Modo debug
    if(debug):
        print("[DECODE] Obtido x: " + str(x_val))
        print("[DECODE] Obtido y: " + str(y_val))

    return x_val, y_val

# Função que gera um par de chaves 
def genKeys(G):
    # Criação do par de chaves (Parametros)
    b = 256 # Tamanho Especifico ao ed25519         
    requested_security_strenght = 32 # Tamanho Especifico ao ed25519 em bytes (32 bytes = 128 bits)  
    keysDigest = hashes.Hash(hashes.SHA512()) # Utilização do sha512 como hash (Especificação do ed25519)

    # --------------------------
    # Passo 1 (Gerar chave privada)
    private_key = secrets.token_bytes(requested_security_strenght)  

    # --------------------------
    # Passo 2 (Calcular a hash da chave privada) 
    keysDigest.update(private_key)
    privateKey_hash = keysDigest.finalize()

    # --------------------------
    # Passo 3 (Gerar a chave publica)
    metade = privateKey_hash[:len(privateKey_hash)//2] # Obter a primeira metade do hash gerado

    # --------------------------
    # Passo 3.1 ("The first 32 octets of H are interpreted as a little-endian integer...")
    metade_byteArray = bytearray(metade)
    metade_byteArray[0] &= 248       # Limpar bits 0,1,2 ("and 11111000" que faz com que os 3 primeiros bits se tornem 0) (O algoritmo utiliza notação little endian)
    metade_byteArray[31] &= 127      # Limpar bit 7 ("and 01111111" que faz com que o ultimo bit se torne 0) (O algoritmo utiliza notação little endian)
    metade_byteArray[31] |= 64       # Definir bit 6 a 0 ("or 01000000" que faz com que o penuultimo bit se torne 1 e mantem os restantes) (O algoritmo utiliza notação little endian)
    metade_novo = bytes(metade_byteArray)

    # --------------------------
    # Passo 4 ("Determine an integer s from hdigest1 using little-endian convention")
    s = int.from_bytes(metade_novo, byteorder="little")

    # --------------------------
    # Passo 5 ("Compute the point [s]G. The corresponding EdDSA public key Q is the encoding of the point [s]G")
    # Criar objeto da curva
    pub_point = G.mult(s) # Obter [s]G
    public_key = encode_points(pub_point.x, pub_point.y) # "The corresponding EdDSA public key Q is the encoding of the point [s]G" 

    if(debug):
        print("[KEYGEN] Public key (hex):", public_key.hex())
        print("[KEYGEN] Private key (hex):", private_key.hex())

    return private_key, public_key

def genSignature(Message, public_key, private_key, G, n):
    # --------------------------
    # Passo 1: Calcular H(private_key) com SHA-512
    digest1 = hashes.Hash(hashes.SHA512())
    digest1.update(private_key)
    privateKeyHash = digest1.finalize() 

    # --------------------------
    # Passo 2: Extrair a segunda metade do hash para computar r (ultimos 32 bytes ja que o output do sha é 64)
    privateKeyHash_half = privateKeyHash[32:]

    # Passo 2.1: r = SHA-512(privateKeyHash_half || Message)
    digest2 = hashes.Hash(hashes.SHA512())
    conc = privateKeyHash_half + Message
    digest2.update(conc)
    r = digest2.finalize()

    # Converter r para inteiro (e reduzir modulo n)
    r_int = int.from_bytes(r, byteorder="little") % n

    # --------------------------
    # Passo 3: Calcular o ponto R = [r]G e codificá‑lo
    R_point = G.mult(r_int) # [r]G na curva de Edwards
    R_encoded = encode_points(R_point.x, R_point.y) # Encoding
    
    # --------------------------
    # Passo 4: Derivar s a partir de H(private_key)
    s_bytes = bytearray(privateKeyHash[:32])  # Pegar os primeiros 32 bytes
    s_bytes[0] &= 0xF8      # Zera os 3 bits menos significativos do primeiro byte (0xF8 = 11111000)
    s_bytes[31] &= 0x7F     # Zera o bit mais significativo do último byte (0x7F = 01111111)
    s_bytes[31] |= 0x40     # Define o penúltimo bit do último byte para 1 (0x40 = 01000000)
    s_scalar = int.from_bytes(s_bytes, byteorder="little") # Valor escalar (int)

    # --------------------------
    # Passo 4.1: Calcular h = SHA-512(R_encoded || public_key || Message)
    digest3 = hashes.Hash(hashes.SHA512())
    digest3.update(R_encoded + public_key + Message)
    h_bytes = digest3.finalize()
    h_int = int.from_bytes(h_bytes, byteorder="little") % n

    # Calcular S = (r_int + h_int * s_scalar) mod n
    S_int = (r_int + h_int * s_scalar) % n
    S_bytes = S_int.to_bytes(32, byteorder="little")

    # --------------------------
    # Passo 5: A assinatura é a concatenação de R_encoded e S_bytes
    signature = R_encoded + S_bytes
    
    if (debug):
        print("[SIGNATURE] Signature (hex):" + str(signature))
              
    return signature

def verify_signature(message, signature, public_key, G, d, p, c, E):
    # Passo 1: "Decode the first half of the signature as a point R"    
    firsthalf = signature[:32]  # R (assinatura = R || S)
    r_point_x, r_point_y = decode_points(firsthalf, d, p)

    # "Decode the public key into a point Q"
    Q_x, Q_y = decode_points(public_key, d, p)
    
    # --------------------------
    # Passo 2: "Convert the second half of the signature (S) to an integer"
    secondhalf = signature[32:]
    s_int = int.from_bytes(secondhalf, byteorder="little")
    
    # Verificar que s está no intervalo [0, n]
    n = ZZ(2**252 + 27742317777372353535851937790883648493)
    if not (0 <= s_int < n):
        raise ValueError("Verificação de assinatura falhou: s fora do intervalo (reject)")
    
    # --------------------------
    # Passo 3: "Form the bit string HashData as the concatenation of R || Q || M"
    # Passo 4: "Compute h = SHA-512(HashData) and interpret as little-endian integer mod n"
    sha = hashes.Hash(hashes.SHA512())
    sha.update(firsthalf + public_key + message)
    hashdata = sha.finalize()
    t = int.from_bytes(hashdata, byteorder="little") % n
    
    # Converter os pontos descodificados em objetos de ponto
    R = ed(curve=E, x=r_point_x, y=r_point_y)
    Q = ed(curve=E, x=Q_x, y=Q_y)
    
    # --------------------------
    # Passo 5: "Check that the verification equation [2c * S]G = [2c]R + (2c * t)Q"
    # Calcular 2^c
    two_c = 2**c
    
    # Lado esquerdo: [2^c * s_int] * G
    lhs = G.mult(two_c * s_int)
    
    # Lado direito = [2^c]R + [2^c * t]Q
    part1 = R.mult(two_c)
    part2 = Q.mult(two_c * t)
    rhs = part1
    rhs.soma(part2)
    
    # Comparar lado esquerdo e direito
    resultado = True
    if lhs.eq(rhs):
        if(debug): print("[VERIFY] Assinatura VÁLIDA!")
    else:
        if(debug): print("[VERIFY] Assinatura INVÁLIDA!")
        resultado = False
    
    return resultado

# Classe que implementa o edDSA (Edwards Digital Signature Algorithm)
class EdDSA():
    def __init__(self):
        # Criação de uma instancia da curva de edwards
        self.E = Ed(p, a, d, ed25519) # Criar instancia do edwards

        # Parametros
        self.G = ed(curve=self.E, x=ed25519["Px"], y=ed25519["Py"]) # Representa o gerador de uma curva de edwards
        self.n = ZZ(2^252 + 27742317777372353535851937790883648493) # Ordem do subgrupo primo
        self.c = 3

        if(debug):
            print("Ponto gerador utilizado:")
            print("[EDDSA]:" + str(ed25519["Px"]))
            print("[EDDSA]:" + str(ed25519["Py"]))
    
    # Permite gerar um par de chaves
    def genKeyPair(self):
        return genKeys(self.G)
    
    # Permite assinar uma mensagem
    def sign(self, message, public_key, private_key):
        return genSignature(message, public_key, private_key, self.G, int(self.n))

    # Permite verificar uma assinatura
    def verify(self, message, signature, public_key):
        return verify_signature(message, signature, public_key, self.G, d, p, self.c, self.E)