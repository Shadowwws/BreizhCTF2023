

# Quelle courbe !

Little disclaimer about this writeup, my maths on this subject are not perfect so i might make some mistakes, if you see one I would be glad to know about it (discord : Shadowwws#8683)

## The problem

We are given the source code of the server:
```py
import struct
from random import SystemRandom
from flag import flag
p = 17585255163044402023
R.<x> = GF(p)[];
f = sum([SystemRandom().randrange(0,p)*x^i for i in range(16)])
C = HyperellipticCurve(f, 0)
J = C.jacobian()
class RNG(object):
	def __init__(self,seed=0):
		if seed == 0:
			self.mul = SystemRandom().randrange(2024,p)
		else:
			self.mul = seed
			self.point = None
		while self.point is None:
			x = SystemRandom().randrange(0,p)
			if len(f(x).sqrt(0,1)) == 0:
				continue
			self.point = J(C(x, min(f(x).sqrt(0,1))))
		self.out = []
	def update(self):
		self.point = self.mul*self.point
		return self.point
	def __call__(self):
		if not self.out:
			u,v = self.update()
			rs = [u[i] for i in range(7)] + [v[i] for i in range(7)]
			assert 0 not in rs and 1 not in rs
			self.out = struct.pack('<'+'Q'*len(rs), *rs)
		r, self.out = self.out[0], self.out[1:]
		return r
	def __iter__(self): return self
	def __next__(self): return self()
	
print(bytes(k^^m for k,m in zip(RNG(2023), flag+b" This is your final boss, enjoy it while you still can:)")).hex())
while True:
	try:
		msg = bytes.fromhex(input("Enter your message : \n"))
		print(bytes(k^^m for k,m in zip(RNG(), msg)).hex())
	except:
		print("Erreur de lecture, merci d’entrer de l’hexadécimale")
```


## The solution

So this is the last one, we are facing an hyperelliptic curve (for an introduction on this topic, see [An Introduction to Elliptic and Hyperelliptic Curve Cryptography and the NTRU Cryptosystem](https://www.esat.kuleuven.be/cosic/publications/article-520.pdf) and [wikipedia](https://en.wikipedia.org/wiki/Hyperelliptic_curve) ) implementation used to encrypt our flag. It selects one base point and one multiplier, and fill a buffer of bytes with the coefficients of the polynomials of the mumford representation of the points.

To explain how this works, we need to know what is the mumford representation, which is the way sagemath stores the points of the Jacobian of an hyperelliptic curve.

The mumford representation consists of two polynomials u(x) and v(x) based on the coordinates (x,y) of the point. There are some properties on these polynomials :
- u(x) is monic
- u(x) divides f(x)−h(x)\*v(x)−v(x)^2 with f(x) and h(x) being in the curve equation.
- deg(v(x)) < deg(u(x)) ≤ g (g is the genus of the curve)

The flag is encrypted using a fixed multiplier equal to 2023. All the coefficients of u(x) are used in the encryption of the flag and all the coefficients of v(x) in the encryption of the known string " This is your final boss, enjoy it while you still can:)"

This means that to get the flag we need to recover u(x). We could do it easily if we knew f(x) but this is not the case so we need to get f(x) first. This is what allows the oracle.

We do know that each root $x_{i}$ of u(x) represents the x-coordinate of a point on the Jacobian, and hence $v(x_{i})^2$ is the y-coordinate.

From that we can gather multiple couple of point ($x_{i},y_{i}$) and combine it to the curve equation $y^2 = f(x)$.

This made me think of lagrange polynomial where you try to find an unique polynomial from its inputs $x_{i}$ and its outputs $y_{i}$.

Here the degree of f(x) is 15 so we need at least 15 points (I take 16 to be safe)
That's what we can do with this part of my solve script :
```py
from pwn import remote
import itertools
import struct

p = 17585255163044402023
R.<x> = GF(p)[]
L = GF(p).algebraic_closure()
r = remote("courbe.ctf.bzh",int(30013))
flag = bytes.fromhex(r.recvline().decode())
pts = []

while len(pts) < 16:
	r.recvline()
	r.sendline(b"00"*8*7*2)
	d = bytes.fromhex(r.recvline().decode())
	
	blocks = [d[i:i+8] for i in range(0, len(d[:8*7]), 8)]
	ui = [int.from_bytes(r, 'little') for r in blocks]
	u = x^7 + sum(val*x^(i) for i,val in enumerate(ui))
	
	roots = [r[0] for r in u.change_ring(L).roots()]
	
	blocks = [d[i+8*7:i+8*7+8] for i in range(0, len(d[8*7:]), 8)]
	vi = [int.from_bytes(r, 'little') for r in blocks]
	v = sum(val*x^(i) for i,val in enumerate(vi))
  
	for root in roots:
		if "^4" in str(root):
			continue
		pts.append((root,v(root)**2))
	print("*"*30)
	
print("Points collected")

RR.<zz> = PolynomialRing(L)
f = RR.lagrange_polynomial(pts)
f = sum(int(coeff.as_finite_field_element()[1])*x^i for i,coeff in enumerate(f.coefficients()))
C = HyperellipticCurve(f, 0)
print(C)
J = C.jacobian()
```
The ugly synthaxe to construct u and v is just taking consecutive blocks of 8 bytes in the ciphertext returned by the server.

---
*Little side note*

After theoremoon's hyperelliptic curve challenge at seccon ([link](https://furutsuki.hatenablog.com/entry/2023/02/13/231456#Crypto-300-hell))  which came out after I finished my first version of my challenge, I learned that we can also do the following to find f(x) :

Remember this relation : u(x) divides f(x)−h(x)*v(x)−$v(x)^2$, this can be transformed in :
```
v(x)^2 = f(x)−h(x)*v(x) mod u(x)
```

Notice that in the challenge, h(x) = 0 so the equality becomes :
```
v(x)^2 = f(x) mod u(x)
```

So if we can get enough pair ( u(x),v(x) ), we can use CRT to recreate f(x).

---

Now that we know f(x), we can recover u(x) from v(x) by using again the relation : $v(x)^2 = f(x) \bmod u(x)$, if we change it a bit we get $v(x)^2 - f(x) = 0 \bmod u(x)$ so by computin $v(x)^2 - f(x)$ we can recover a multiple of u(x), then we just go through the divisors of that polynomial and one of them will be u(x). 

Final code:
```py
from pwn import remote
import itertools
import struct

p = 17585255163044402023

R.<x> = GF(p)[]
L = GF(p).algebraic_closure()

#r = remote("0.0.0.0",int(1337))
r = remote("courbe.ctf.bzh",int(30013))

flag = bytes.fromhex(r.recvline().decode())

pts = []

while len(pts) < 16:
	r.recvline()
	r.sendline(b"00"*8*7*2)
	d = bytes.fromhex(r.recvline().decode())
	blocks = [d[i:i+8] for i in range(0, len(d[:8*7]), 8)]
	ui = [int.from_bytes(r, 'little') for r in blocks]
	u = x^7 + sum(val*x^(i) for i,val in enumerate(ui))

	roots = [r[0] for r in u.change_ring(L).roots()]

	blocks = [d[i+8*7:i+8*7+8] for i in range(0, len(d[8*7:]), 8)]
	vi = [int.from_bytes(r, 'little') for r in blocks]
	v = sum(val*x^(i) for i,val in enumerate(vi))
	
	for root in roots:
		if "^4" in str(root):
			continue
		pts.append((root,v(root)**2))
	print("*"*30)

print("Points collected")

RR.<zz> = PolynomialRing(L)
f = RR.lagrange_polynomial(pts)
f = sum(int(coeff.as_finite_field_element()[1])*x^i for i,coeff in enumerate(f.coefficients()))
C = HyperellipticCurve(f, 0)
print(C)
J = C.jacobian()

flag, known = flag[:-56], flag[-56:]

known = bytes([c^^d for c,d in zip(known,b" This is your final boss, enjoy it while you still can:)")])

blocks = [known[i:i+8] for i in range(0, len(known), 8)]
vi = [int.from_bytes(r, 'little') for r in blocks]
v = sum(val*x^(i) for i,val in enumerate(vi))

factors = list((v^2 - f).change_ring(R).factor()) + [(1,1)]*3

print(f"got {len(factors)} factors")

for factor in itertools.combinations(factors,4):
	u = prod([fac[0] for fac in factor])
	try:
		rs = [int(u[i]) for i in range(7)]
		keystream = struct.pack('<'+'Q'*len(rs), *rs)
		flog = bytes([c^^d for c,d in zip(keystream,flag)])
		if b"BZH" in flog:
			print(flog)
			break
	except Exception as e:
		print(u,e)
		continue
```

Flag : `BZHCTF{53cc0n_m4d3_m3_ch4n63_7h15_1_h0p3_y0u_3nj0y3d_17}`

---
After note:
I wanted to do a challenge based on hyperelliptic curve because it's something we don't see often in ctfs, a bit unfortunatly there was on at SECCON Finals this year and later at pbctf so it was not so much unseen. But I think it was still pertinent to give this challenge because it was already prepared and it's always fun to solve challenges.

### Shadowwws
