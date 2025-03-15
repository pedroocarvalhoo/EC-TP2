
from edwards25519 import Edwards25519, EdPoint

def test_edwards25519():
    print("Iniciando testes da curva Edwards 25519...")
    
    # Criar a curva
    curve = Edwards25519()
    print("\n1. Curva criada com sucesso")
    
    # Exibir constantes da curva
    print("\n2. Constantes da curva:")
    for key, value in curve.constants.items():
        print(f"  {key}: {value}")
    
    # Verificar ordem e cofator
    L, h = curve.order()
    print(f"\n3. Ordem do subgrupo: {L}")
    print(f"   Cofator: {h}")
    
    # Verificar o ponto gerador
    P = curve.create_point()
    print(f"\n4. Ponto gerador em coordenadas Edwards:")
    print(f"   Px: {P.x}")
    print(f"   Py: {P.y}")
    
    # Verificar se o ponto gerador pertence à curva
    print(f"\n5. O ponto gerador pertence à curva: {curve.is_edwards(P.x, P.y)}")
    
    # Verificar conversão para curva elíptica
    EC_point = curve.ed2ec(P.x, P.y)
    print(f"\n6. Ponto gerador convertido para curva elíptica:")
    print(f"   {EC_point}")
    
    # Verificar a conversão inversa
    ed_x, ed_y = curve.ec2ed(EC_point)
    print(f"\n7. Conversão de volta para coordenadas Edwards:")
    print(f"   Px: {ed_x}")
    print(f"   Py: {ed_y}")
    
    # Verificar se os pontos são iguais após conversão
    print(f"   Conversão preserva o ponto: {ed_x == P.x and ed_y == P.y}")
    
    # Teste de duplicação de pontos
    P2 = P.double()
    print(f"\n8. 2P usando método double():")
    print(f"   2P.x: {P2.x}")
    print(f"   2P.y: {P2.y}")
    
    # Teste de adição de pontos
    P_plus_P = P.add(P)
    print(f"\n9. 2P usando método add(P, P):")
    print(f"   (P+P).x: {P_plus_P.x}")
    print(f"   (P+P).y: {P_plus_P.y}")
    
    print(f"   Métodos double() e add() produzem mesmo resultado: {P2.eq(P_plus_P)}")
    
    # Teste de multiplicação escalar simples
    k1 = 3
    k2 = 5
    P3 = P.mult(k1)
    print(f"\n10. {k1}P usando mult():")
    print(f"    {k1}P.x: {P3.x}")
    print(f"    {k1}P.y: {P3.y}")
    
    # Teste de multiplicação escalar
    P5 = P.mult(k2)
    print(f"\n11. {k2}P usando mult():")
    print(f"    {k2}P.x: {P5.x}")
    print(f"    {k2}P.y: {P5.y}")
    
    # Teste especial para verificar associatividade de maneira consistente com o código original
    P3_plus_P5 = P3.add(P5)
    P8 = P.mult(k1 + k2)
    print(f"\n12. Teste de associatividade: {k1}P + {k2}P == ({k1}+{k2})P:")
    print(f"    {k1}P + {k2}P = ({P3_plus_P5.x}, {P3_plus_P5.y})")
    print(f"    ({k1}+{k2})P = ({P8.x}, {P8.y})")
    print(f"    Associatividade preservada: {P3_plus_P5.eq(P8)}")
    
    # Teste de ordem do subgrupo
    PL = P.mult(L)
    print(f"\n13. Teste de ordem do subgrupo (L*P):")
    print(f"    L*P.x: {PL.x}")
    print(f"    L*P.y: {PL.y}")
    print(f"    L*P é o ponto neutro: {PL.x == 0 and PL.y == 1}")
    
    # Teste com escalar grande
    large_scalar = 123456789
    P_large = P.mult(large_scalar)
    print(f"\n14. Teste com escalar grande ({large_scalar}):")
    print(f"    {large_scalar}*P.x: {P_large.x}")
    print(f"    {large_scalar}*P.y: {P_large.y}")
    print(f"    O ponto resultante pertence à curva: {curve.is_edwards(P_large.x, P_large.y)}")
    
    print("\nTodos os testes concluídos!")

if __name__ == "__main__":
    test_edwards25519()