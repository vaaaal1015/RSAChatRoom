import random
class RSA_Algrithm:
    def isPrime(self, n):
        for i in range(2,n):
            if(n%i == 0):
                return False
        return True
    def computeGCD(self, x, y):
        while(y):
            x, y = y, x % y
        return x
    def generatePandQ(self):
        p = 0
        q = 0
        primes = [i for i in range(10,1000) if self.isPrime(i)]
        while(p==q):
            p = random.choice(primes)
            q = random.choice(primes)
        return p, q
    def gennerateTwoKeys(self):
        p, q  = self.generatePandQ()
        n = p*q
        phi = (p-1) * (q-1)
        for e in range(2,phi):
            if (self.computeGCD(e, phi) == 1):
                break
        d = pow(e, -1, phi)
        return ((e, n),(d, n))

    
    
    