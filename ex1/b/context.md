# IND-CPA (Indistinguishability under Chosen-Plaintext Attack)

- Uma cifra é IND-CPA segura se:
    - Um adversário escolhe m0 e m1
    - Escolhemos um texto aleatório
    - Ciframos o que escolhemos
    - Através da cifra, o adversário não é capaz de saber que texto foi escolhido por nós
    - Ou seja, a chance de ele acertar é 50% (tipo moeda ao ar)

# IND-CCA (Indistinguishability under Chosen-Ciphertext Attack)

- Uma cifra é IND-CCA segura se:
    - Existe um adversário com um oráculo de decifrar
    - Ele pode decifrar qualquer texto, menos o do desafio
    - Adversário escolhe m0 e m1
    - Ciframos m0 ou m1
    - O adversário não deve conseguir saber que texto foi cifrado com probabilidade maior que 50%

# Transformação de Fujisaki-Okamoto

Converte um esquema IND-CPA para IND-CCA\

### Como funciona?

- Dado $m$, gera-se $r$ (aleatoriamente)
- Usamos $r$ para baralhar a cifra, assim o $ciphertext$ passa a depender de $m$ e $r$
- o $ciphertext  = (c_1,c_2)$ em que $c_1 = (m,r)$ e $c_2 = H(r)$

### Para cifrar:

- extraímos $r$ de $c_2$
- usamos $r$ para decifrar $c_1$ e recuperar $m$
 
 
