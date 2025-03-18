# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
from edElGamal import EdwardsElGamal

# Instanciar a classe que implementa o ElGamal em curvas de Edwards
ee = EdwardsElGamal()

# Parametros da curva 
q = ee.L     # Ordem do subgrupo da curva
G = ee.G     # Ponto gerador da curva

def assinar(curve_G, priv_key, msg_points):
    """
    Assina uma mensagem representada como uma lista de pontos na curva.
    Retorna a assinatura (R_sign, s).
    """
    k = random.randint(1, q-1)
    R_sign = curve_G.mult(k)
    # Serializa os pontos: concatena as coordenadas dos pontos em msg_points e de R_sign
    msg_bytes = b"".join([str(P.x).encode('utf-8') + str(P.y).encode('utf-8') for P in msg_points])
    msg_bytes += str(R_sign.x).encode('utf-8') + str(R_sign.y).encode('utf-8')
    e = int(hashlib.sha256(msg_bytes).hexdigest(), 16) % q
    s = (k + e * priv_key) % q
    return (R_sign, s)

def verificar_assinatura(curve_G, pub_key, msg_points, assinatura):
    """
    Verifica a assinatura Schnorr sobre uma lista de pontos.
    Retorna True se válida, False caso contrário.
    """
    (R_sign, s) = assinatura
    msg_bytes = b"".join([str(P.x).encode('utf-8') + str(P.y).encode('utf-8') for P in msg_points])
    msg_bytes += str(R_sign.x).encode('utf-8') + str(R_sign.y).encode('utf-8')
    e = int(hashlib.sha256(msg_bytes).hexdigest(), 16) % q
    lhs = curve_G.mult(s)
    rhs = R_sign.add(pub_key.mult(e))
    return (lhs.x == rhs.x and lhs.y == rhs.y)



# Parâmetros do protocolo
n = 5   # Número total de mensagens disponíveis
k = 2   # Número de mensagens que o receptor deseja obter
mensagens = [10, 20, 30, 40, 50]  # Exemplo de mensagens numéricas

# Geração de par de chaves do receptor para o esquema ElGamal
sk_R = random.randint(1, q-1)  # Chave privada do receptor
pk_R = G.mult(sk_R)           # Chave pública do receptor

# Geração de par de chaves para assinatura do receptor
sk_R_sign = random.randint(1, q-1)
pk_R_sign = G.mult(sk_R_sign)

# Seleção dos índices escolhidos pelo receptor
indices_escolhidos = [1, 3]  # Exemplo: receptor escolhe os índices 1 e 3

# Construção da requisição OT pelo receptor: para cada índice, gera um ponto R_j
R_list = []
for j in range(n):
    u_j = random.randint(1, q-1)
    R_j = G.mult(u_j)
    if j in indices_escolhidos:
        R_j = R_j.add(pk_R)
    R_list.append(R_j)

# Assinatura da requisição com a chave privada do receptor
assinatura_req = assinar(G, sk_R_sign, R_list)

# O receptor envia (R_list, assinatura_req) para o emissor

# -----------------------------------------------------------------------------
# O EMISSOR PROCESSA A REQUISIÇÃO
# -----------------------------------------------------------------------------

# Geração de chaves para assinatura do emissor
sk_S_sign = random.randint(1, q-1)
pk_S_sign = G.mult(sk_S_sign)

# Emissor verifica a assinatura da requisição
req_valida = verificar_assinatura(G, pk_R_sign, R_list, assinatura_req)
print("Assinatura da requisição válida?", req_valida)

# Emissor cifra cada mensagem m_j usando ElGamal:
# Para cada mensagem, gera um nonce r_j, calcula c1_j = r_j * G, 
# representa a mensagem como M_j = m_j * G e calcula o segredo compartilhado S_j = r_j * R_j,
# obtendo c2_j = M_j + S_j.
cifrases = []
for j, m_j in enumerate(mensagens):
    r_j = random.randint(1, q-1)
    c1_j = G.mult(r_j)
    M_j = G.mult(m_j)
    S_j = R_list[j].mult(r_j)
    c2_j = M_j.add(S_j)
    cifrases.append((c1_j, c2_j))

# Emissor assina a resposta (lista dos pares cifrados)
assinatura_resp = assinar(G, sk_S_sign, [c1 for (c1, c2) in cifrases] + [c2 for (c1, c2) in cifrases])

# Emissor envia (cifrases, assinatura_resp) para o receptor

# -----------------------------------------------------------------------------
# O RECEPTOR PROCESSA A RESPOSTA
# -----------------------------------------------------------------------------

# Receptor verifica a assinatura da resposta do emissor
resp_valida = verificar_assinatura(G, pk_S_sign, [c1 for (c1, c2) in cifrases] + [c2 for (c1, c2) in cifrases], assinatura_resp)
print("Assinatura da resposta válida?", resp_valida)

# Receptor decifra somente as mensagens escolhidas:
# Para cada índice escolhido j, calcula S_j = sk_R * c1_j e recupera M_j_dec = c2_j - S_j.
# Em seguida, realiza uma busca exaustiva para encontrar o escalar m_j tal que M_j_dec = m_j * G.
mensagens_decifradas = {}
for j in indices_escolhidos:
    c1_j, c2_j = cifrases[j]
    S_j = c1_j.mult(sk_R)
    # Calcula o inverso aditivo de S_j: -S_j é equivalente a S_j multiplicado por (q-1)
    M_j_dec = c2_j.add(S_j.mult(q-1))
    decifrado = None
    # Busca exaustiva (assumindo m_j pequeno)
    for candidate in range(0, 100):
        if G.mult(candidate).x == M_j_dec.x and G.mult(candidate).y == M_j_dec.y:
            decifrado = candidate
            break
    mensagens_decifradas[j] = decifrado

# Exibição das mensagens decifradas pelo receptor
print("\nMensagens decifradas pelo receptor:")
for j, msg in mensagens_decifradas.items():
    print("Índice {}: Mensagem = {}".format(j, msg))

# Resumo final
print("\nResumo Final:")
print("Mensagens originais do emissor:", mensagens)
print("Índices escolhidos pelo receptor:", indices_escolhidos)
print("Mensagens decifradas:", [mensagens_decifradas[j] for j in indices_escolhidos])