---
title: 2024 SekaiCTF Crypto Writeup
tags: ["CTF", "Crypto"]
category: Writeups
published: 2024-08-29
description: "包含3道简单题，另外几个还在尝试复现。"
draft: false
---

赛中没看`マスタースパーク`实在是亏麻了，赛后多看了几眼才发现压根不需要攻击CSIDH本身QQ

以及，Neobeo我一直是你的粉丝啊（

<!--more-->

## Some Trick

> task

```python
import random
from secrets import randbelow, randbits
from flag import FLAG

CIPHER_SUITE = randbelow(2**256)
print(f"oPUN_SASS_SASS_l version 4.0.{CIPHER_SUITE}")
random.seed(CIPHER_SUITE)

GSIZE = 8209
GNUM = 79

LIM = GSIZE**GNUM


def gen(n):
    p, i = [0] * n, 0
    for j in random.sample(range(1, n), n - 1):
        p[i], i = j, j
    return tuple(p)


def gexp(g, e):
    res = tuple(g)
    while e:
        if e & 1:
            res = tuple(res[i] for i in g)
        e >>= 1
        g = tuple(g[i] for i in g)
    return res



def enc(k, m, G):
    if not G:
        return m
    mod = len(G[0])
    return gexp(G[0], k % mod)[m % mod] + enc(k // mod, m // mod, G[1:]) * mod


def inverse(perm):
    res = list(perm)
    for i, v in enumerate(perm):
        res[v] = i
    return res


G = [gen(GSIZE) for i in range(GNUM)]


FLAG = int.from_bytes(FLAG, 'big')
left_pad = randbits(randbelow(LIM.bit_length() - FLAG.bit_length()))
FLAG = (FLAG << left_pad.bit_length()) + left_pad
FLAG = (randbits(randbelow(LIM.bit_length() - FLAG.bit_length()))
        << FLAG.bit_length()) + FLAG

bob_key = randbelow(LIM)
bob_encr = enc(FLAG, bob_key, G)
print("bob says", bob_encr)
alice_key = randbelow(LIM)
alice_encr = enc(bob_encr, alice_key, G)
print("alice says", alice_encr)
bob_decr = enc(alice_encr, bob_key, [inverse(i) for i in G])
print("bob says", bob_decr)

```

在置换群上实作的一个类似Diffie-Hellman的加密，但是random seed给了你所以加密用的置换是可以求得的。enc函数的递归可以看作是一个mod进制展开式，先爆破拿到bob_key之后就可以逐位爆破flag了。

> exp

```python
def base_expan(n, m):
    expan = []
    while n!=0:
        expan.append(n%m)
        n = n//m
    return expan

def inverse(perm):
    res = list(perm)
    for i, v in enumerate(perm):
        res[v] = i
    return res

def gexp(g, e):
    res = tuple(g)
    while e:
        if e & 1:
            res = tuple(res[i] for i in g)
        e >>= 1
        g = tuple(g[i] for i in g)
    return res


G = 
Ginv = [inverse(i) for i in G]
GSIZE = 8209
bob_decr = 
alice_encr = 
bob_encr = 
x = base_expan(alice_encr, GSIZE)
y = base_expan(bob_decr, GSIZE)
i = 0
bob_key = []

# try to find bobkey
for g in Ginv:
    if i >= len(x):
        tmp = gexp(g,0)
    else:
        tmp = gexp(g, x[i])
    for t in range(len(tmp)):
        if tmp[t] == y[i]:
            bob_key.append(t)
            break
    i += 1
bob_key_re = bob_key[::-1]
print(bob_key_re)
bobkey = 0
for i in range(len(bob_key_re)):
    bobkey *= GSIZE
    bobkey += bob_key_re[i]
print(bobkey)
print(bobkey<GSIZE**79)
from tqdm import trange
flag = []
bobkey_expan = base_expan(bobkey, GSIZE)
bob_encr_expan = base_expan(bob_encr, GSIZE)
print(bob_encr_expan,bobkey_expan)
count = 0

# crack flag "bit by bit"
for g in G:
    for i in trange(GSIZE):
        if count>= len(bobkey_expan):
            if(gexp(g,i)[0]==(bob_encr_expan[count])):
                flag.append(i)
                break
        else:
            if(gexp(g,i)[bobkey_expan[count]]==(bob_encr_expan[count])):
                flag.append(i)
                break
    count += 1
from Crypto.Util.number import long_to_bytes
flag_int = 0
flag_re = flag[::-1]
print(flag_re)
for i in range(len(flag_re)):
    flag_int *= GSIZE
    flag_int += flag_re[i]
print(flag_int)

# remove the padding
for i in range(flag_int.bit_length()):
    tmp = long_to_bytes(flag>>i)
    if b'{' in tmp:
        print(tmp)

```

## はやぶさ

> task

```python
from falcon import falcon
from flag import flag

def main():
    sk = falcon.SecretKey(64)
    pk = falcon.PublicKey(sk)
    print(pk)
    print(sk)
    print(sk.sign(b"Can you break me").hex())
    your_sig = bytes.fromhex(input("what is your sig? >"))


    if pk.verify(b"Can you break me", your_sig):
        print("well done!!")
        print(flag)
        exit()

    print("Broken your wing T_T")


main()
```

> up.sh

```bash
git clone https://github.com/tprest/falcon.py.git

mv falcon.py falcon

echo "import os
import sys

sys.path.append(os.path.dirname(__file__))
" > ./falcon/__init__.py
```

读一下[falcon](https://github.com/tprest/falcon.py.git)的代码后知道这是个NTRU签名系统，私钥是多项式f、g、F、G，公钥是多项式h，所在的环是

$$\frac{\mathbb{Z}_{q}[x]}{x^{64}+1}$$

所以就是商环上的NTRU签名伪造，拿格子直接打就行，但是coding就比较麻烦...

> exp

```python
import falcon
from ntrugen import *
import encoding
# from timeout_decorator import timeout
import copy

HEAD_LEN = 1
SALT_LEN = 40
SEED_LEN = 56

def Babai_closest_vector(B, target):
    # Babai's Nearest Plane algorithm
    M = B.BKZ(block_size=20)
    G = M.gram_schmidt()[0]
    small = target
    for _ in range(1):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -= M[i] * c
    return target - small

def get_fgFG(mat):
    lll = mat.BKZ()
    print(lll)

    cands = []
        
    for cand in lll:
        print(cand)
        f = cand[:blocksize]
        g = cand[blocksize:]

        if gs_norm(f, g, q) > (1.17 ** 2) * q:
            continue
        f_ntt = ntt(f)
        if any((elem == 0) for elem in f_ntt):
            continue
        try:
            F, G = ntru_solve(f, g)
            F = [int(coef) for coef in F]
            G = [int(coef) for coef in G]
            cands.append([f, g, F, G])
        # If the NTRU equation cannot be solved, a ValueError is raised
        # In this case, we start again
        except ValueError:
            continue

    return cands

def solve(h):
    n = int(64)
    sk = falcon.SecretKey(n)
    pk = falcon.PublicKey(sk)
    q = 12 * 1024 + 1
    salt = b"a"*SALT_LEN
    H = pk.hash_to_point(b"Can you break me", salt)
    K = int(sqrt(q))

    blocksize = len(h)

    one = matrix.identity(blocksize)
    qblock = q * one

    hblock = matrix(blocksize, blocksize)
    rh = list(reversed(h))
    for i in range(blocksize):
        for j in range(blocksize):
            hblock[i,j] = rh[(j-i) % blocksize]

    for j in range(blocksize-1):
        for i in range(j+1):
            hblock[i,j] = -1 * hblock[i,j]


    Hblock = matrix.circulant(H).transpose()
    zero = matrix(blocksize, blocksize)
    Kblock = K * one

    mat = block_matrix([
        [one, hblock],
        [zero,qblock]
    ])

    HH = copy.deepcopy(H)
    for i in range(blocksize):
        index = ((blocksize-1)*2 - i) % blocksize
        print(index)
        HH[i] = H[((blocksize-1)*2 - i) % blocksize]
    target = vector([0] * blocksize + HH)
    print("target:", target)
    res = Babai_closest_vector(mat, target)
    print("res:", res)
    print("hblock")
    print(hblock)
    print("hoge:", vector(GF(q), res[:blocksize]) * hblock)
    s1 = list(reversed(res[:blocksize]))
    print(sk.myverify(b"Can you break me", salt, list(reversed(res[:blocksize]))))
    print("--------------------------------------------------")
    s = sk.mysign(b"Can you break me", salt)
    sk.myverify(b"Can you break me", salt, s[1])
    print(s)
    print(res)

    logn = {
        2: 1,
        4: 2,
        8: 3,
        16: 4,
        32: 5,
        64: 6,
        128: 7,
        256: 8,
        512: 9,
        1024: 10
    }
    Params = {
        # FalconParam(2, 2)
        2: {
            "n": 2,
            "sigma": 144.81253976308423,
            "sigmin": 1.1165085072329104,
            "sig_bound": 101498,
            "sig_bytelen": 44,
        },
        # FalconParam(4, 2)
        4: {
            "n": 4,
            "sigma": 146.83798833523608,
            "sigmin": 1.1321247692325274,
            "sig_bound": 208714,
            "sig_bytelen": 47,
        },
        # FalconParam(8, 2)
        8: {
            "n": 8,
            "sigma": 148.83587593064718,
            "sigmin": 1.147528535373367,
            "sig_bound": 428865,
            "sig_bytelen": 52,
        },
        # FalconParam(16, 4)
        16: {
            "n": 16,
            "sigma": 151.78340713845503,
            "sigmin": 1.170254078853483,
            "sig_bound": 892039,
            "sig_bytelen": 63,
        },
        # FalconParam(32, 8)
        32: {
            "n": 32,
            "sigma": 154.6747794602761,
            "sigmin": 1.1925466358390344,
            "sig_bound": 1852696,
            "sig_bytelen": 82,
        },
        # FalconParam(64, 16)
        64: {
            "n": 64,
            "sigma": 157.51308555044122,
            "sigmin": 1.2144300507766141,
            "sig_bound": 3842630,
            "sig_bytelen": 122,
        },
        # FalconParam(128, 32)
        128: {
            "n": 128,
            "sigma": 160.30114421975344,
            "sigmin": 1.235926056771981,
            "sig_bound": 7959734,
            "sig_bytelen": 200,
        },
        # FalconParam(256, 64)
        256: {
            "n": 256,
            "sigma": 163.04153322607107,
            "sigmin": 1.2570545284063217,
            "sig_bound": 16468416,
            "sig_bytelen": 356,
        },
        # FalconParam(512, 128)
        512: {
            "n": 512,
            "sigma": 165.7366171829776,
            "sigmin": 1.2778336969128337,
            "sig_bound": 34034726,
            "sig_bytelen": 666,
        },
        # FalconParam(1024, 256)
        1024: {
            "n": 1024,
            "sigma": 168.38857144654395,
            "sigmin": 1.298280334344292,
            "sig_bound": 70265242,
            "sig_bytelen": 1280,
        },
    }

    from encoding import compress

    int_header = 0x30 + logn[n]
    header = int(int_header).to_bytes(1, "little")
    enc_s = compress(s1, Params[n]['sig_bytelen'] - HEAD_LEN - SALT_LEN)
    s = header + salt + enc_s 
    return s

from pwn import remote
io = remote("hayabusa.chals.sekai.team", int(1337), ssl=True)
print(io.recvline())
print(io.recvline())
h = io.recvline()
print(io.recvuntil('what is your sig? >'))

h = eval(h.split(b'=')[1])
print(h)

n = int(64)
sk = falcon.SecretKey(n)
pk = falcon.PublicKey(sk)
print(h)
s = solve(h)
print(sk.verify(b"Can you break me", s))
io.sendline(s.hex())
io.interactive()
```

## *マスタースパーク

> task

```python
from Crypto.Util.number import *
import os
from timeout_decorator import timeout, TimeoutError

load("GA.sage")

FLAG = os.getenv("FLAG")
secret = getPrime(256)
choice = set()


@timeout(60)
def T_T(p, primes, secret):

    assert isPrime(p)
    assert len(primes) > 3

    Fp = GF(p)
    Fp2.<j> =  GF(p ^ 2, modulus=x ^ 2 + 1)
    ls = len(factor(p + 1)) - 2

    m = ceil((sqrt(p) ** (1 / ls) - 1) / 2)
    alice_priv = [randrange(-m, m + 1) for _ in range(len(primes))]
    bob_priv = [randrange(-m, m + 1) for _ in range(len(primes))]
    EC = montgomery(Fp2, 0)
    P = EC.gens()[0]
    k = 1
    alice_pub, Q = group_action(p, primes, Fp, Fp2, 0, alice_priv, k * P)
    share_bob, Q = group_action(p, primes, Fp, Fp2, alice_pub, bob_priv, secret * Q)
    bob_pub, P = group_action(p, primes, Fp, Fp2, 0, bob_priv, P)
    share_alice, P = group_action(p, primes, Fp, Fp2, bob_pub, alice_priv, P)
    return P, Q


def check(p):
    assert isPrime(p)
    assert p.bit_length() <= 96
    assert ((p + 1) // 4) % 2 == 1
    prime_list = []
    cnt = 0

    for p, i in factor((p + 1) // 4):
        assert not p in choice
        if i > 1:
            cnt += 1
            choice.add(p)
            assert int(p).bit_length() <= 32
        else:
            prime_list.append(p)
            choice.add(p)

    assert all([int(p).bit_length() <= 16 for p in prime_list])
    assert cnt == 1

    return prime_list


def main():
    while True:
        try:
            p = int(input("input your prime number or secret > "))
            if int(p).bit_length() == 256:
                if p == secret:
                    print(FLAG)
                    exit()
                print("not flag T_T")
            else:
                prime_list = check(p)
                P, Q = T_T(p, prime_list, secret)
                print(P.xy())
                print(Q.xy())
        except:
            print("T_T")
            exit()
main()
```

> GA.sage

```python
from random import randint

# I received advice from Mitsu to write this program. I appreciate it very much

def montgomery(Fp2, A):
    return EllipticCurve(Fp2, [0, A, 0, 1, 0])

def to_montgomery(Fp, Fp2, E, G):
    Ep = E.change_ring(Fp).short_weierstrass_model()
    a, b = Ep.a4(), Ep.a6()
    P.<x> = PolynomialRing(Fp)
    r = (x^3 + a*x + b).roots()[0][0]
    s = sqrt(3 * r^2 + a)
    if not is_square(s):
        s = -s
    A = 3 * r / s
    phi = E.isomorphism_to(EllipticCurve(Fp2, [0, A, 0, 1, 0]))
    return Fp(A), phi(G)

def group_action(p, primes, Fp, Fp2, pub, priv, G):
    E = montgomery(Fp2, pub)
    es = priv[:]
    while any(es):
        x = Fp.random_element()
        P = E.lift_x(x)
        s = 1 if P[1] in Fp else -1
        S = [i for i, e in enumerate(es) if sign(e) == s and e != 0]
        k = prod([primes[i] for i in S])
        Q = ((p + 1) // k) * P
        
        for i in S:
            R = (k // primes[i]) * Q
            if R.is_zero():
                continue
            phi = E.isogeny(R)
            E = phi.codomain()
            Q, G = phi(Q), phi(G)
            es[i] -= s
            k //= primes[i]
    return to_montgomery(Fp, Fp2, E, G)

```

基于CSIDH的题目，会对传入的素数检查是否等于secret，是则输出flag，否则在通过额外的一些检查后生成超奇异椭圆曲线，接着在上面CSIDH。

虽然我对CSIDH一窍不通，但是题目把映射后的点也输出了：

> P = EC.gens()[0] # 把这里的P记作G

那么返回给我们的其实是

$$Q = \phi_{b}(\phi_{a}(secret*G))$$
$$P = \phi_{a}(\phi_{b}(G))$$

所以有

$$Q = secret*P$$

一个ECDLP而已。

题目的二次曲线的阶是拿我们构造的(p+1)//4的素因子组成的，所以只需要控制p光滑之后就能求解ECDLP，最后crt起来就行。

> exp

```python
# Sage
from Crypto.Util.number import *
import os
from pwn import remote, subprocess



load("GA.sage")
# PoW抄了鸡块师傅的写法，感谢ta的代码让手动挡变成自动挡
# 侵删
def runcmd(command):
    ret = subprocess.run(command,shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,encoding="utf-8")
    if ret.returncode == 0:
        print("success:",ret)
        return ret.stdout.strip()
    else:
        print("error:",ret)

io = remote(*'master-spark.chals.sekai.team 1337'.split(), ssl=True)
io.recvuntil(b'proof of work: ')
cmd = io.recvline().strip().decode()
res = runcmd(cmd)
io.sendlineafter(b'solution: ', res.encode())



def chal(p):
    print(">p", p)
    io.recvuntil(b"input your prime number or secret > ")
    io.sendline(str(p).encode())
    P= io.recvline().strip()
    Q= io.recvline().strip()
    return P, Q

import random
memo = set()
def make_prime():
    primes = []
    for i in range(2**7+256):
        if isPrime(i) and (i not in memo):
            primes.append(i)

    print(len(primes))
    for i in range(100000):
        p = 4
        l = random.sample(primes, 5)
        for pp in l:
            p *= pp
        r = random.sample(l, 1)[0]
        p *= r * r
        if isPrime(int(p-1)) and (p // 4) % 2 == 1:
            for ll in l:
                memo.add(ll)
            print("l:", l)
            return int(p-1)

def make_primes():
    res = []
    for i in range(10):
        res.append(make_prime())
    return res

def solve1(p):
    Fp = GF(p)
    Fp2.<j> =  GF(p ^ 2, modulus=x ^ 2 + 1)
    P, Q = chal(p)
    P = eval(P)
    Q = eval(Q)
    A = -(P[0]^3 - P[1]^2 + P[0])/P[0]^2
    EC = montgomery(Fp2, A) # order: (p+1)^2
    P = EC(P)
    Q = EC(Q)
    print(P)
    print(P.discrete_log(Q))
    return P.discrete_log(Q), P.order()

def check1(num):
    print(">p", p)
    return False

vals = []
mods = []
primes = make_primes()
for p in primes:
    print("==================================================", p, "==================================================")
    val, m = solve1(int(p))
    vals.append(val)
    mods.append(m)
    if lcm(mods) > 2**256:
        break

print(vals)
print(mods)
print(lcm(mods))
import copy

length = len(mods)


for mask in range(2**length):
    vals2 = copy.deepcopy(vals)
    for j in range(length):
        if ((mask >> j) & 1) == 1:
            vals2[j] = -vals2[j]
    try:
        cand = int(crt(vals2, mods))
        if cand.bit_length() == 256:
            print("check:", cand)
            io.sendline(str(cand).encode())
            print(io.recvline())
            print(io.recvline())
            print(io.recvline())

    except:
        pass
```
