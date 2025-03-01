# EC-TP2

Este trabalho usa SageMath nas suas implementações


1. Pretende-se construir em torno de uma cifra assimétrica um conjunto de técnicas criptográficas destinadas a fins distintos. Apesar de todas as alíneas do problema poderem ser  respondidas com a maioria das cifras assimétricas clássicas ou pós-quânticas, neste problema vamos exemplificar o processo com uma técnica simples da família Diffie-Hellman nomeadamente a cifra assimétrica ElGamal com parâmetros de segurança $$\,\lambda\,$$.
    1. Implemente um esquema  PKE $$\,\mathsf{ElGamal}(\lambda)\,$$ (ver Capítulo 4) num subgrupo de ordem prima $$\,q\,$$,  com $$\,|q|\geq \lambda\,$$, do grupo multiplicativo $$\,\mathbb{F}^\ast_p\,$$ com $$\,p\,$$ um primo que verifica $$\,|p| \geq \lambda\times|\lambda|$$ . Identifique o gerador de chaves e os algoritmos de cifra de decifra neste esquema. Identifique o núcleo deterministico do algoritmo de cifra.
    2. Supondo que a cifra que implementou é IND-CPA segura (de novo Capítulo 4), usando a transformação de Fujisaki-Okamoto implemente um PKE que seja IND-CCA seguro.
    3. A partir de (b) construa um esquema de KEM que seja IND-CCA seguro.
    4. A partir de (b) construa uma implementação de um protocolo autenticado de “Oblivious Transfer” $$\,\kappa$$-out-of-$$n\,$$.


2. Construir uma classe Python que implemente o  EcDSA a partir do “standard” FIPS186-5
    1. A implementação deve conter funções para assinar digitalmente e verificar a assinatura.
    2. A implementação da classe deve usar  uma das “Twisted Edwards Curves” definidas no standard e escolhida  na iniciação da classe: a curva  “edwards25519” ou “edwards448”.


3. Usando a experiência obtida na resolução dos problemas 1 e 2, e usando, ao invés  do grupo abeliano multiplicativo $$\,\mathbb{F}_p^\ast\,$$,  o  grupo abeliano aditivo que usou na pergunta 2,   
    1. Construa ambas as versões  IND-CPA segura e IND-CCA segura do esquema de cifra ElGamal em curvas elípticas.
    2. Construa uma implementação em curvas elípticas de um protocolo autenticado de “Oblivious Transfer” $$\,\kappa$$-out-of-$$n\,$$.