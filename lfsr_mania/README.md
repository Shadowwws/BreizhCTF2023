
# LFSR mania

## The problem

We are given the source code:
```py
from random import randint, sample
from Crypto.Util.number import isPrime, bytes_to_long
flag = b"REDACTED"
def getSecurePrime(sieve):
	while True:
		l = sample(sieve,33)
		p = 2
		for f in l:
			p*=f
		if isPrime(p+1):
			return p+1
			
class LFSR:
	def __init__(self):
		self._s = [randint(0,1) for _ in range(56)]
		self._t = [0,2,20,23,55]
		for _ in range(randint(56,2023)):
			self._clock()
	def _clock(self):
		b = self._s[0]
		c = 0
		for t in self._t: c ^= self._s[t]
			self._s = self._s[1:] + [c]
		return b
	def stream(self, length):
		return [self._clock() for _ in range(length)]
		
rng = LFSR()
sieve = [int("".join(list(map(str, rng.stream(20)))),2) for _ in range(100)]

assert len(set(sieve)) == 100

p = getSecurePrime(sieve)
q = getSecurePrime(sieve)
n = p*q
print(f"n = {n}")
print(f"c = {pow(bytes_to_long(flag),0x10001,n)}")
```
And this output:
```
n = 32541127249676048274585294402402082041511346507140236125495367181025972412444596253951837525730727065130470995715340459822998513905305027287744911728598215459428687319994758662626235616728836195964751714247360647511726490408053929996688465628986053017961048202770753597787338727666252712403987020209769680439318652190578663503570207150781051067370023042416640000001
c = 2415413610087299939810617039650527297967694065662688028887277389318647900367452472147640886200014619727675108895968999911805080445054088264331314710831725399596057093601387084458600514464288817534610697880503331477205172488927877771388096528107170147223329601398494646270223732932367150735270360700520360821859025997610152427468326489059226944840699701327692437725
```

## The solution

So we are facing a RSA challenge where the primes are generated with a special function. The function is taking a list of primes from a sieve, multiply them, add one and check if it's prime.

The tricky point is how the sieve is constructed, those primes are coming from an LFSR and most importantly are only 20 bits. So we know that phi (which equal (p-1)\*(q-1)) has small factors and we can use pollard p-1 attack. You need to optimize it a bit otherwise it takes some time (30 min or something like that).
I decided to not take to the power M (product of the primes under $2^{21}$) every time but rather add one prime at each loop, it's faster and take 8 minutes on my computer.

Script:
```py
from Crypto.Util.number import isPrime, long_to_bytes
from math import gcd
from tqdm import tqdm
e = 0x10001
n = 32541127249676048274585294402402082041511346507140236125495367181025972412444596253951837525730727065130470995715340459822998513905305027287744911728598215459428687319994758662626235616728836195964751714247360647511726490408053929996688465628986053017961048202770753597787338727666252712403987020209769680439318652190578663503570207150781051067370023042416640000001
c = 2415413610087299939810617039650527297967694065662688028887277389318647900367452472147640886200014619727675108895968999911805080445054088264331314710831725399596057093601387084458600514464288817534610697880503331477205172488927877771388096528107170147223329601398494646270223732932367150735270360700520360821859025997610152427468326489059226944840699701327692437725
a = 2
primes = [i for i in tqdm(range(1,2**21)) if isPrime(i)]
nb = 0
M = 1
for nb in tqdm(range(0,len(primes))):
	 M*=primes[nb]
x = pow(a,M,n)
i = 0

while True:
	p = gcd(x-1,n) 
	if p != n and p != 1:
		break
	x = pow(x,primes[i%len(primes)],n)
	i+=1
	
assert n%p == 0
q = n//p
phi = (p-1)*(q-1)
d = pow(e,-1,phi)
print(long_to_bytes(pow(c,d,n)))
```

Flag : BZHCTF{4_l177l3_p0ll4rd_n07_7h3_b34r_b7w}

### Shadowwws
