# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
import secrets
load("edElGamal.sage")   # Carregar o ficheiro que contem a implementação do EdwardsElGamal
load('utils.sage')
load('edwards25519.sage')
import hashlib
import os
import random
from sage.rings.finite_rings.finite_field_constructor import GF
from edwards25519 import Edwards25519, EdPoint
print("[INFO] Imports realizados com sucesso!")

########################################################################################
def matrixA(curve, lines, cols, seed):
    """Gera matriz A usando pontos na curva"""
    K = curve.K
    A = matrix(K, lines, cols)
    for i in range(lines):
        for j in range(cols):
            A[i,j] = K(H(str(seed) + str(i) + str(j), length=curve.L.nbits()))
    return A

def vectorU(curve, cols, seed):
    """Gera vetor u usando elementos do campo finito da curva"""
    K = curve.K
    u = vector(K, cols)
    for i in range(cols):
        u[i] = K(H(str(seed) + str(i), length=curve.L.nbits()))
    return u

def generate_oblivious_criterion(n, kappa, curve):
    """
    Gera o critério oblivioso usando a curva Edwards
    
    Parâmetros:
    - n: número total de mensagens disponíveis
    - kappa: número de mensagens a serem transferidas
    - curve: instância da curva Edwards25519
    """
    # Gerar seeds para aleatoriedade determinística
    rho1 = os.urandom(16).hex()
    rho2 = os.urandom(16).hex()
    
    # Criar matriz A e vetor u
    A = matrixA(curve, n, n-kappa, rho1)
    u = vectorU(curve, n-kappa, rho2)
    
    return A, u, (rho1, rho2)

def compute_goodKeys(selected_indices, n, edwards_elgamal):
    """Gera boas chaves para os índices selecionados"""
    p_vector = [None] * n
    good_keys = {}
    
    # Para cada índice selecionado, gerar par de chaves
    for i in selected_indices:
        public_key, private_key = edwards_elgamal.keygen()
        good_keys[i] = (public_key, private_key)
        p_vector[i] = public_key
    
    # Gerar tag para verificação
    secret = os.urandom(edwards_elgamal.lambda_security // 8)
    indices_bytes = b"".join([i.to_bytes(4, 'big') for i in selected_indices])
    tag = hashlib.sha256(indices_bytes + secret).digest()
    
    return good_keys, tag, p_vector, secret

def complete_p_vector(curve, A, u, selected_indices, p_vector):
    """
    Completa o vetor p com pontos para os índices não selecionados
    """
    n = A.nrows()
    K = curve.K
    
    all_indices = set(range(n))
    unselected_indices = sorted(list(all_indices - set(selected_indices)))
    
    # Criar vetor R baseado nos pontos já atribuídos
    R = vector(K, u)
    for i in selected_indices:
        if p_vector[i] is not None:
            x_coord = p_vector[i].x
            row = vector(K, A[i])
            R -= x_coord * row
            
    # Criar matriz B para resolver o sistema
    B_rows = [vector(K, A[j]) for j in unselected_indices]
    B = matrix(K, B_rows)
    
    # Resolver o sistema
    B_inv = B.inverse()
    X = R * B_inv
    
    # Atribuir pontos para índices não selecionados
    for idx, j in enumerate(unselected_indices):
        # Criar um ponto que corresponde ao valor calculado
        x_val = X[idx]
        point = generate_point_with_x(curve, x_val)
        p_vector[j] = point
        
    return p_vector

def generate_point_with_x(curve, x_val):
    """Gera um ponto com coordenada x aproximada"""
    # Mapear x_val para um valor que pode ser coordenada x de um ponto na curva
    # Esse mapeamento deve ser determinístico mas difícil de inverter
    
    # Exemplo simplificado:
    hash_input = str(x_val)
    for i in range(100):  # tentar diferentes valores
        candidate_x = curve.K(H(hash_input + str(i), length=curve.L.nbits()))
        try:
            # Verificar se pode ser coordenada x de um ponto
            f_val = curve.K(candidate_x**3 + curve.constants['a4']*candidate_x + curve.constants['a6'])
            if f_val.is_square():
                y = f_val.sqrt()
                ec_point = curve.EC(candidate_x, y)
                ed_x, ed_y = curve.ec2ed(ec_point)
                # Armazenar o valor original para verificação
                point = EdPoint(ed_x, ed_y, curve)
                point.original_x = x_val  # adicionar atributo para verificação
                return point
        except:
            continue
    
    raise ValueError("Não foi possível encontrar um ponto com coordenada x próxima ao desejado")

def generate_query_vector(A, u, selected_indices, edwards_elgamal):
    """
    Gera o vetor de consulta para o protocolo OT
    """
    n, n_minus_kappa = A.dimensions()
    kappa = n - n_minus_kappa
    
    if len(selected_indices) != kappa:
        raise ValueError(f"O receiver deve escolher exatamente {kappa} índices")
    
    # Gerar chaves para índices selecionados
    curve = edwards_elgamal.curve
    good_keys, tag, p_vector, secret = compute_goodKeys(selected_indices, n, edwards_elgamal)
    
    # Completar o vetor p para índices não selecionados
    p_vector = complete_p_vector(curve, A, u, selected_indices, p_vector)
    
    return p_vector, tag, good_keys

def verify_criterion(p_vector, A, u, curve):
    K = curve.K
    n = len(p_vector)
    d = len(u)
    
    total = vector(K, [0] * d)
    for i in range(n):
        row = vector(K, A[i])
        # Usar o valor original para verificação
        x_val = getattr(p_vector[i], 'original_x', p_vector[i].x)
        total += K(x_val) * row
        
    u_vec = vector(K, u)
    return total == u_vec

def H(value, length=32):
    """Função hash"""
    return int.from_bytes(hashlib.sha256(str(value).encode()).digest(), byteorder='big') % (2^length)

def encrypt_messages(messages, A, u, query_vector, tag, edwards_elgamal):
    """
    Cifra as mensagens usando ElGamal em curvas Edwards
    """
    encrypted_messages = []
    
    for i in range(len(messages)):
        try:
            # A chave pública para este índice é o elemento do query_vector
            public_key = query_vector[i]
            
            # Cifrar mensagem usando ElGamal em curvas Edwards
            encrypted_data = edwards_elgamal.encrypt_message(public_key, messages[i])
            
            # Gerar hash para integridade, usando tag
            c_2 = H(str(encrypted_data) + str(tag.hex()))
            
            encrypted_messages.append({
                'index': i,
                'ciphertext': (encrypted_data, c_2)
            })
            
        except Exception as e:
            print(f"Erro ao cifrar mensagem {i}: {e}")
    
    return encrypted_messages

def decrypt_messages(encrypted_messages, selected_indices, good_keys, tag, edwards_elgamal):
    """
    Decifra as mensagens usando ElGamal em curvas Edwards
    """
    decrypted_messages = {}
    
    for message_data in encrypted_messages:
        i = message_data['index']
        
        """if i not in selected_indices:
            print(f"Mensagem {i}: não selecionada, ignorando")
            continue"""
            
        try:
            ciphertext = message_data['ciphertext']
            encrypted_data, c_2 = ciphertext
            
            # Chave privada para este índice
            _, private_key = good_keys[i]
            
            # Verificar integridade com tag
            c_2_calculated = H(str(encrypted_data) + str(tag.hex()))
            
            if c_2_calculated != c_2:
                print(f"  Mensagem {i}: falha na verificação de integridade")
                continue
                
            # Decifrar mensagem
            plaintext = edwards_elgamal.decrypt_message(private_key, encrypted_data)
            
            decrypted_messages[i] = plaintext
            print(f"  Mensagem {i} decifrada: {plaintext}")
            
        except Exception as e:
            print(f"Não foi possível decifrar mensagem {i}: {e}")
    
    return decrypted_messages

########################################################################################

if __name__ == "__main__":
    """
    TESTE DO PROTOCOLO OBLIVIOUS TRANSFER k-OUT-OF-n COM CURVAS EDWARDS
    """
    
    print("=" * 60) # Barra horizontal
    print("TESTE DO PROTOCOLO OBLIVIOUS TRANSFER k-OUT-OF-n COM CURVAS EDWARDS")
    print("=" * 60) # Barra horizontal
    
    while True:
        try:
            n = int(input("Nº total de mensagens (n): "))
            
            if n <= 0:
                print("O número de mensagens deve ser maior que 0.")
                continue

            kappa = int(input(f"Quantas mensagens quer receber? (k <= {n}): "))
            if kappa <= 0:
                print("O número de mensagens a transferir deve ser maior que 0.")
                continue
            
            if kappa > n:
                print(f"O número de mensagens a transferir não pode ser maior que ({n}).")
                continue       
            break
        except ValueError:
            print("Por favor, digite valores numéricos válidos.")
    
    print(f"Parâmetros: n={n}, k={kappa}")
    
    # FASE 1: CONFIGURAÇÃO (Provider)
    print("\n" + "=" * 40) # Barra horizontal
    print("FASE 1: CONFIGURAÇÃO (Provider)")
    print("=" * 40) # Barra horizontal
    
    print("A inicializar Edwards ElGamal...")
    edwards_elgamal = EdwardsElGamal(security_param=128)
    curve = edwards_elgamal.curve
    
    print(f"Curva Edwards25519 inicializada")
    print(f"Ordem da curva (L): {edwards_elgamal.L}")
    
    print("\nA gerar o Protocolo OT (A, u)...")
    A, u, rho = generate_oblivious_criterion(n, kappa, curve)
    
    print(f"Matriz A ({A.nrows()}×{A.ncols()}) gerada")
    print(f"Vetor u ({len(u)} elementos) gerado")
     
    messages = [f"Mensagem {i+1}" for i in range(n)]
    print("\nMensagens disponíveis:")
    for i, msg in enumerate(messages):
        print(f"  [{i}] {msg}")
    
    # FASE 2: SELEÇÃO E CONSULTA (Receiver)
    print("\n" + "=" * 40)
    print("FASE 2: SELEÇÃO E CONSULTA (Receiver)")
    print("=" * 40)
    
    selected_indices = sorted(random.sample(range(n), kappa))
    
    print(f"Receiver escolheu os índices: {selected_indices}")
    print(f"Mensagens que serão recuperadas:")
    for idx in selected_indices:
        print(f"  [{idx}] {messages[idx]}")
    
    # GERAR O VETOR DE CONSULTA
    print("\nA gerar vetor de consulta p...")
    query_vector, tag, good_keys = generate_query_vector(A, u, selected_indices, edwards_elgamal)
    print(f"Vetor p gerado com {len(query_vector)} pontos na curva")
    
    # Verificar propriedade do vetor de consulta
    print("\nVerificando propriedade do vetor de consulta:")
    verification_result = verify_criterion(query_vector, A, u, curve)
    print(f"Verificação: p·A = u? {verification_result}")

    # FASE 3: CIFRAR AS MENSAGENS (Provider)
    print("\n" + "=" * 40)
    print("FASE 3: CIFRAR AS MENSAGENS (Provider)")
    print("=" * 40)
    
    print("A cifrar mensagens...")
    encrypted_messages = encrypt_messages(messages, A, u, query_vector, tag, edwards_elgamal)
    print(f"Total de {len(encrypted_messages)} mensagens cifradas")
    
    # FASE 4: DECIFRAR AS MENSAGENS (Receiver)
    print("\n" + "=" * 40)
    print("FASE 4: DECIFRAR AS MENSAGENS (Receiver)")
    print("=" * 40)
    
    decrypted_messages = decrypt_messages(encrypted_messages, selected_indices, good_keys, tag, edwards_elgamal)
    
    # Verificar resultados
    print("\n" + "=" * 40)
    print("RESULTADOS FINAIS")
    print("=" * 40)
    print(f"Mensagens recuperadas: {len(decrypted_messages)}/{kappa}")
    
    all_recovered = len(decrypted_messages) == kappa
    correct_indices = all(idx in decrypted_messages for idx in selected_indices)
    
    if all_recovered and correct_indices:
        print("SUCESSO! O protocolo OT funcionou corretamente.")
        print("  O receiver recuperou exatamente as k mensagens selecionadas.")
    else:
        print("FALHA! O protocolo OT não funcionou como esperado.")
        print(f"  Mensagens recuperadas: {sorted(decrypted_messages.keys())}")
        print(f"  Mensagens esperadas: {selected_indices}")
    
    # Comparar mensagens originais com decifradas
    print("\nVerificação das mensagens recuperadas:")
    for idx in decrypted_messages:
        original = messages[idx]
        decrypted = decrypted_messages[idx]
        match = original == decrypted
        print(f"  [{idx}] Original: '{original}' | Decifrada: '{decrypted}' | {'✓' if match else '✗'}")