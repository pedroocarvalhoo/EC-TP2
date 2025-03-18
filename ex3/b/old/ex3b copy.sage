# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
import secrets
load("edDSA.sage") # Carregar o ficheiro que contem a implementação do EdDSA
load("edElGamal.sage")   # Carregar o ficheiro que contem a implementação do EdwardsElGamal
load('utils.sage')
load('edwards25519.sage')
print("[INFO] Imports realizados com sucesso!")

# Instanciar a classe que implementa o EdDSA
edDSA = EdDSA()
print("[INFO] Instanciação da classe EdDSA realizada com sucesso!")

# Instanciar a classe que implementa o ElGamal em curvas de Edwards
ee = EdwardsElGamal()
print("[INFO] Instanciação da classe EdwardsElGamal realizada com sucesso!")

############################################
n=1000 # Numero de mensagens disponiveis
chosen = [1, 3] # Mensagens escolhidas
############################################

# ETAPA 0: Criação de pares de chaves para utilização com as assinaturas
rec_sk, rec_pk = edDSA.genKeyPair() # Par de chaves a ser utilizado pelo recetor nas suas assinaturas
sender_sk, sender_pk = edDSA.genKeyPair() # Par de chaves a ser utilizado pelo emissor nas suas assinaturas

# ETAPA 1: Preparação do receptor
receiver_pub_keys = [] # Chaves públicas do recetor
receiver_priv_keys = [] # Chaves privadas do recetor (None quando não foi escolhido)

# O recetor vai criar as suas chaves 
for j in range(n):
    (pub, priv) = ee.keygen()
    if j in chosen: # Se a mensagem for escolhida 
        receiver_pub_keys.append(pub)
        receiver_priv_keys.append(priv)
    else:
        receiver_pub_keys.append(pub)
        receiver_priv_keys.append(None)

# ETAPA 2: Enviar requisição (Simulada)
# Permite receber uma lista de pontos e transforma em uma string/mensagem
def serialize_points(points):
    s = ""
    for P in points:
        # Aqui concatenamos as coordenadas x e y de cada ponto com um separador
        s += str(P.x) + "," + str(P.y) + ";"
    return s

req_message = serialize_points(receiver_pub_keys)
req_message_bytes = str.encode(req_message)

# Irei assinar a mensagem do recetor 
req_message_signature = edDSA.sign(req_message_bytes, rec_pk, rec_sk) # Assinar o request 
print("[RECETOR] Requisição assinada e enviada!")

# VAMOS ASSUMIR QUE ENTRE ESTAS ETAPAS SE ENCONTRA IMPLEMENTADA A COMUNICAÇÃO ENTRE O EMISSOR E O RECETOR

############################################ EMISSOR
# O emissor vai verificar a assinatura 
sig_ver = edDSA.verify(req_message_bytes, req_message_signature, rec_pk) # Verificação da assinatura

# Verificar se assinatura é válida ou não
if (sig_ver):
    print("[EMISSOR] Assinatura válida recebida!")
else:
    raise Exception("[EMISSOR] Assinatura inválida!")

# Agora vamos cifrar as mensagens
q = ee.getL() # Obter a ordem do grupo
for j in range(n):
    r_j = secrets.randbelow(q - 1) + 1 # Escolher um escalar aleatorio (Valor r)