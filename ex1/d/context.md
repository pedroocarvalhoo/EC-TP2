# OBLIVIOUS TRANSFER

Mecanismo de transferencia de informação entre Provider e Receiver.\

1. Provider disponibiliza $n$ itens enumerados como $m_1$, $m_2$,...,$m_3$. A única informação publica é o numero de mensagens $n$
2. O receiver avisa o provider que pretende receber $k$ das $n$ mensagens
3. Caso o provider aceite os agentes trocam uma sequencia de mensagens
4. No fim o receiver conhece exatamente $k$ mensagens e ignora as $n-k$ restantes.
5. O provider não sabe que $k$ mensagens o provider passou a conhecer


## Oblivious Criterion (OC)

**$OC$** é um circuito aritmético $C_kn$ que recebe como input $p = {p_1,...,p_n}$ de chaves publicas e só aceita esse vetor quando mais de $k$ componentes de $p$ são chaves públicas da forma pk$(s)$.
As restantes $n-k$ chaves públicas são calculadas a partir das primeiras são geradas a partir das $k$ primeiras chaves, assim o circuito é aceite pelo $C_kn$

O $OC$ consegue decidir de se p exitem $k$ componentes que são chaves publicas associadas a chaves privadas $s$, quem são escolhidas pelo Receiver (chaves boas) ou se são chaves más (calculadas a partir das chaves publicas geradas). O protocolo assegura que existem $k$ chaves boas, mas não especifica estas chaves.


### Para Gerar as chaves

- Cada chave pública (boa ou má) é codificada por um inteiro em $Z_q$ com $q$ primo.
- Uma matriz $$\,\mathsf{A} \in \mathbb{Z}_q^{n\times(n-\kappa)}\,$$ e um vetor $$\,\mathsf{u}\neq 0\in \mathbb{Z}_q^{n-\kappa}\,$$. Estes são gerados por um XOF a partir de uma "seed". A seed é gerada de forma aleatoria e os restantes elementos são construidos com o XOF até verificarem as condições.
- $$\;\mathsf{p} \times \mathsf{A}\,=\,\mathsf{u}$$ 


# FASES DO PROTOCOLO

1. O provider gera o critério $C_kn$ e envia ao receiver

2. Receiver escolhe um conjunto com k elementos $$\,I \subset \{1,n\}\,$$
    - temos o grupo $(1,k)$ e a partir deste temos que gerar (1,n)
    1. Gera-se um segredo $s$ e usando um XOF constroi-se $k$ chaves privadas $s_1,...,s_k$
    2. Para cada i pertencente a $(1,k)$ gera-se chaves públicas $v_i$ e esse valor vai para a componente e(i) do vetor p, portanto $p_e(i) = v_i$
    3. Gera-se i, tah de autenticação para I e s $tag = hash(I,s)$

    4. As chaves más são escolhidas resolvendo o sitema de equações $pxA = u$

    5. O receiver envia ao provider a tag e o vetor p


3. Provider determina $C_kn(p)$
    - Se nao for aceite o processo é abortado
    - Se for aceite