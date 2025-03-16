import sage.all
from sage.all import GF, ZZ, EllipticCurve, Mod, is_prime, factor

class Edwards25519:
    """
    Implementação da curva Edwards 25519 seguindo estritamente o código original.
    """
    
    def __init__(self):
        # Parâmetros fixos da curva 25519
        self.p = 2**255 - 19
        self.K = GF(self.p)
        self.a = self.K(-1)
        self.d = -self.K(121665)/self.K(121666)
        
        # Calcular constantes da curva
        A = 2*(self.a + self.d)/(self.a - self.d)
        B = 4/(self.a - self.d)
        
        alfa = A/(3*B)
        s = B
        
        a4 = s**(-2) - 3*alfa**2
        a6 = -alfa**3 - a4*alfa
        
        self.constants = {
            'a': self.a,
            'd': self.d,
            'A': A,
            'B': B,
            'alfa': alfa,
            's': s,
            'a4': a4,
            'a6': a6
        }
        
        # Criar curva elíptica equivalente
        self.EC = EllipticCurve(self.K, [a4, a6])
        
        # Definir o subgrupo e ponto gerador
        self.L = ZZ(2**252 + 27742317777372353535851937790883648493)
        self.h = 8  # Cofator
        
        # Coordenadas do ponto gerador em Edwards
        self.Px = self.K(15112221349535400772501151409588531511454012693041857206046113283949847762202)
        self.Py = self.K(46316835694926478169428394003475163141307993866256225615783033603165251855960)
        
        # Converter para a curva elíptica
        self.P = self.ed2ec(self.Px, self.Py)
    
    def is_edwards(self, x, y):
        """
        Verifica se um ponto (x, y) pertence à curva de Edwards.
        """
        a = self.constants['a']
        d = self.constants['d']
        x2 = x**2
        y2 = y**2
        return a*x2 + y2 == 1 + d*x2*y2
    
    def ed2ec(self, x, y):
        """
        Mapeia um ponto da curva Edwards para a curva elíptica equivalente.
        """
        if (x, y) == (0, 1):
            return self.EC(0)  # Ponto no infinito
        
        z = (1 + y)/(1 - y)
        w = z/x
        alfa = self.constants['alfa']
        s = self.constants['s']
        return self.EC(z/s + alfa, w/s)
    
    def ec2ed(self, P):
        """
        Mapeia um ponto da curva elíptica para a curva Edwards.
        """
        if P == self.EC(0):
            return (0, 1)  # Elemento neutro
        
        x, y = P.xy()
        alfa = self.constants['alfa']
        s = self.constants['s']
        u = s*(x - alfa)
        v = s*y
        return (u/v, (u-1)/(u+1))
    
    def order(self):
        """
        Retorna a ordem do subgrupo e o cofator.
        """
        return (self.L, self.h)
    
    def create_point(self, x=None, y=None):
        """
        Cria um ponto na curva Edwards.
        """
        if x is None or y is None:
            return EdPoint(self.Px, self.Py, self)
        
        if self.is_edwards(x, y):
            return EdPoint(x, y, self)
        else:
            raise ValueError("O ponto não pertence à curva Edwards 25519")


class EdPoint:
    """
    Implementação de pontos na curva Edwards, seguindo o código original.
    """
    def __init__(self, x, y, curve):
        self.curve = curve
        self.x = x
        self.y = y
        self.w = x*y
    
    def eq(self, other):
        """
        Verifica se dois pontos são iguais.
        """
        return self.x == other.x and self.y == other.y
    
    def copy(self):
        """
        Cria uma cópia do ponto atual.
        """
        return EdPoint(self.x, self.y, self.curve)
    
    def zero(self):
        """
        Retorna o elemento neutro da curva.
        """
        return EdPoint(0, 1, self.curve)
    
    def sim(self):
        """
        Retorna o simétrico (inverso) do ponto.
        """
        return EdPoint(-self.x, self.y, self.curve)
    
    def soma(self, other):
        """
        Adiciona outro ponto ao ponto atual, alterando o ponto atual.
        """
        a = self.curve.constants['a']
        d = self.curve.constants['d']
        delta = d*self.w*other.w
        self.x, self.y = (self.x*other.y + self.y*other.x)/(1+delta), (self.y*other.y - a*self.x*other.x)/(1-delta)
        self.w = self.x*self.y
        
    def add(self, other):
        """
        Adiciona outro ponto ao ponto atual, retornando um novo ponto.
        """
        result = self.copy()
        result.soma(other)
        return result
    
    def duplica(self):
        """
        Duplica o ponto atual, alterando o ponto atual.
        """
        a = self.curve.constants['a']
        d = self.curve.constants['d']
        delta = d*(self.w)**2
        self.x, self.y = (2*self.w)/(1+delta), (self.y**2 - a*self.x**2)/(1-delta)
        self.w = self.x*self.y
    
    def double(self):
        """
        Duplica o ponto atual, retornando um novo ponto.
        """
        result = self.copy()
        result.duplica()
        return result
    
    def mult(self, n):
        """
        Multiplicação escalar, seguindo o algoritmo original.
        """
        # Obter representação binária do escalar n módulo L
        m = Mod(n, self.curve.L).lift().digits(2)
        Q = self.copy()
        A = self.zero()
        
        for b in m:
            if b == 1:
                A.soma(Q)
            Q.duplica()
        
        return A

    def create_point(self, x=None, y=None, skip_check=False):
        """
        Cria um ponto na curva Edwards.
        
        Args:
            x: coordenada x (opcional)
            y: coordenada y (opcional)
            skip_check: se True, não verifica se o ponto está na curva
            
        Returns:
            EdPoint: um ponto na curva
        """
        if x is None or y is None:
            return EdPoint(self.Px, self.Py, self)
        
        if skip_check or self.is_edwards(x, y):
            return EdPoint(x, y, self)
        else:
            a = self.constants['a']
            d = self.constants['d']
            x2 = x**2
            y2 = y**2
            left = a*x2 + y2
            right = 1 + d*x2*y2
            
            if abs(left - right) < 1e-10:
                return EdPoint(x, y, self)
            else:
                raise ValueError("O ponto não pertence à curva Edwards 25519")