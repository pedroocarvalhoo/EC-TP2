# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
import ED
from sage.all import *

# Parametros para a curva 
p = 2^448 - 2^224 - 1
K = GF(p)
a = K(1)
d = K(-39081)

ed448= {
    'b'  : 456, ## tamanho das assinaturas e das chaves públicas
    'Px' : K(224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710) ,
    'Py' : K(298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660) ,                                          
    'L'  : ZZ(2^446 - 13818066809895115352007386748515426880336692474882178609894547503885) ,
    'n'  : 447,     ## tamanho dos segredos: os dois primeiros bits são 0 e o último é 1.
    'h'  : 4        ## cofactor
}

E = Ed(p,a,d)
#print(E.EC)
#print()
print(E.order())
Px = ed448['Px']; Py = ed448['Py']
print(E.is_edwards(Px,Py))
E.ed2ec(Px,Py)