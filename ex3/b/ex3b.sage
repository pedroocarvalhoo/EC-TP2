# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
load("edDSA.sage") # Carregar o ficheiro que contem a implementação do EdDSA
load("edElGamal.sage")   # Carregar o ficheiro que contem a implementação do EdwardsElGamal
load('utils.sage')
load('edwards25519.sage')

# Instanciar a classe que implementa o EdDSA
edDSA = EdDSA()

# Instanciar a classe que implementa o ElGamal em curvas de Edwards
ee = EdwardsElGamal()

############################################
n=1000 # Numero de mensagens disponiveis
chosen = [1, 3] # Mensagens escolhidas
############################################

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