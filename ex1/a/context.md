# PKE (Public Key Encryption)

É um método de criptografia assimétrica que usa um par de chaves (pública e privada) para proteger dados.\
Qualquer PKE é determinado por três algoritmos: geração de chaves, cifra e decifra.

# ElGamal 
Check: https://www.youtube.com/watch?v=hyZsbqT7Q2A \
No contexto de ataques IND-CPA apenas a geração de chaves e cifra são relevantes e apenas a chave pública é relevante.

- $ GenKeys(λ) $ → $\lambda$ é o parâmetro de segurança
    - gerar aleatoriamente um primo $\,q \approx 2^\lambda$
    - gerar um primo $p$  tal que  $\,\mathbb{F}_p^\ast\,$ tem um sub-grupo de ordem $\,q\,$ ; calcular um gerador $g$ desse sub-grupo
    - gerar aleatoriamente  $\,0 <s < q\,$ ,  a chave privada
    - calcular e  revelar  a chave pública   $\,\mathsf{pk} \equiv \langle p,q, g,g^s\rangle$

- $ Enc(pk,m)  $ → a mensagem $m$ é um elemento de $\mathbb{F}_p^\ast$
    - obter elementos públicos  $\,p,q,g,g^s \,\gets\,\mathsf{pk}$
    - gerar aleatoriamente  $\,0 <\omega < q$ 
    - calcular  $\,\gamma \gets g^\omega\;$ e $\,\kappa \gets (g^s)^\omega\,$.
    - construir  o criptograma $\,\mathbf{c}\gets \langle\,\gamma\,,\, m\times\kappa\,\rangle\,$ ; $ κ=γ^8 $

## Legenda das Variáveis no Esquema de ElGamal (IND-CPA)

### **Key Generation (`GenKeys(λ)`)**  
- **`λ`** → Parâmetro de segurança (define o tamanho dos números usados).  
- **`q`** → Número primo grande, aproximadamente $2^λ$, define a ordem do subgrupo.  
- **`p`** → Número primo tal que  tem um subgrupo de ordem \( q \).  
- **`g`** → Gerador do subgrupo de ordem \( q \).  
- **`s`** → Chave privada, escolhida aleatoriamente no intervalo (0, q) .  
- **`pk`** → Chave pública 

---

### **Encrypt (`Enc(pk, m)`)**  
- **`m`** → Mensagem a ser cifrada 
- **`ω`** → Valor aleatório escolhido no intervalo  (0, q).  
- **`γ`** → Valor intermediário  
- **`κ`** → Chave de cifra temporária  
- **`c`** → Criptograma resultante   
- **`κ = γ^s`** → Definição alternativa da chave de cifra temporária.
​​

