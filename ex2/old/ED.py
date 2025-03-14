# Estruturas criptográficas 2024-2025
# Grupo 02 - Miguel Ângelo Martins Guimarães (pg55986) e Pedro Miguel Oliveira Carvalho (pg55997)

# Imports
from sage.all import *

# Edwards class
class Ed(object):
    def __init__(self,p, a, d , ed = None):
        assert a != d and is_prime(p) and p > 3
        K        = GF(p) 
  
        A =  2*(a + d)/(a - d)
        B =  4/(a - d)
    
        alfa = A/(3*B) ; s = B

        a4 =  s^(-2) - 3*alfa^2
        a6 =  -alfa^3 - a4*alfa
        
        self.K = K
        self.constants = {'a': a , 'd': d , 'A':A , 'B':B , 'alfa':alfa , 's':s , 'a4':a4 , 'a6':a6 }
        self.EC = EllipticCurve(K,[a4,a6]) 
        
        if ed != None:
            self.L = ed['L']
            self.P = self.ed2ec(ed['Px'],ed['Py'])  # gerador do gru
        else:
            self.gen()
    
    def order(self):
        # A ordem prima "n" do maior subgrupo da curva, e o respetivo cofator "h" 
        oo = self.EC.order()
        n,_ = list(factor(oo))[-1]
        return (n,oo//n)
    
    def gen(self):
        L, h = self.order()       
        P = O = self.EC(0)
        while L*P == O:
            P = self.EC.random_element()
        self.P = h*P ; self.L = L
  
    def is_edwards(self, x, y):
        a = self.constants['a'] ; d = self.constants['d']
        x2 = x^2 ; y2 = y^2
        return a*x2 + y2 == 1 + d*x2*y2

    def ed2ec(self,x,y):      ## mapeia Ed --> EC
        if (x,y) == (0,1):
            return self.EC(0)
        z = (1+y)/(1-y) ; w = z/x
        alfa = self.constants['alfa']; s = self.constants['s']
        return self.EC(z/s + alfa , w/s)
    
    def ec2ed(self,P):        ## mapeia EC --> Ed
        if P == self.EC(0):
            return (0,1)
        x,y = P.xy()
        alfa = self.constants['alfa']; s = self.constants['s']
        u = s*(x - alfa) ; v = s*y
        return (u/v , (u-1)/(u+1))


# Points class of ED
class ed(object):
    def __init__(self,pt=None,curve=None,x=None,y=None):
        if pt != None:
            self.curve = pt.curve
            self.x = pt.x ; self.y = pt.y ; self.w = pt.w
        else:
            assert isinstance(curve,Ed) and curve.is_edwards(x,y)
            self.curve = curve
            self.x = x ; self.y = y ; self.w = x*y
    
    def eq(self,other):
        return self.x == other.x and self.y == other.y
    
    def copy(self):
        return ed(curve=self.curve, x=self.x, y=self.y)
    
    def zero(self):
        return ed(curve=self.curve,x=0,y=1)
    
    def sim(self):
        return ed(curve=self.curve, x= -self.x, y= self.y)
    
    def soma(self, other):
        a = self.curve.constants['a']; d = self.curve.constants['d']
        delta = d*self.w*other.w
        self.x, self.y  = (self.x*other.y + self.y*other.x)/(1+delta), (self.y*other.y - a*self.x*other.x)/(1-delta)
        self.w = self.x*self.y
        
    def duplica(self):
        a = self.curve.constants['a']; d = self.curve.constants['d']
        delta = d*(self.w)^2
        self.x, self.y = (2*self.w)/(1+delta) , (self.y^2 - a*self.x^2)/(1 - delta)
        self.w = self.x*self.y
        
    def mult(self, n):
        m = Mod(n,self.curve.L).lift().digits(2)   ## obter a representação binária do argumento "n"
        Q = self.copy() ; A = self.zero()
        for b in m:
            if b == 1:
                A.soma(Q)
            Q.duplica()
        return A