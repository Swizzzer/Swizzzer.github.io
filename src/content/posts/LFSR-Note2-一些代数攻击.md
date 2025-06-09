---
title: LFSR Note 2 一些代数攻击
tags: ["Crypto", "流密码"]
category: Notes
published: 2025-04-15
---

记录一下对LFSR的一些代数打法

<!-- more -->

# 存在线性递推关系

单个LFSR的输出存在线性递推关系，当给出的输出足够长时，这一弱点可以被直接攻破。

## 序列递推式基础

对于一个序列 $\left\{a_r\right\}$，其`minimal polynomial`是唯一的一个首一多项式 $g$，满足：若 $\left\{a_r\right\}$ 满足线性递推关系 $a_{j+k} + b_{j-1} a_{j-1+k} + \cdots + b_0 a_k = 0$（对所有 $k \geq 0$ 成立），则 $g$ 整除多项式 $x^j + \sum_{i=0}^{j-1} b_i x^i$。

写成初等数学的形式大概长这样：

若一个序列 $\left\{a_r\right\}$ 满足：
$$
\sum_{j=0}^m r_j a_{i-j}=0, \forall i \geq m
$$

其中 $r_0=1$ ，则记序列$\left\{r_0, \cdots, r_m\right\}$为其递推式，$m$ 称为该递推式的`阶数`。
数列 $\left\{a_i\right\}$ 的最短递推式即为阶数最小的递推式。对最短递推式$\left\{r_0, \cdots, r_m\right\}$，
$$\sum_{i=0}^mr_ix^{m-i}$$
称为$\left\{a_r\right\}$的minimal polynomial。

当然，minimal polynomial不一定存在。如果存在，那么称其递推式的阶数/多项式本身的度为序列$\left\{a_r\right\}$的`线性复杂度`。

## Berlekamp-Massey算法
### 原理
虽然我一贯是调包侠的作风，不过还是稍微记录下算法的原理吧。以下文字摘抄自[该blog](https://www.cnblogs.com/came11ia/p/16597854.html)

我们的问题是，在数列$a$已知的情况下，如何求出其最短线性递推式$r$。

考虑增量法，假设我们已经求出了 $a_{1 \cdots i-1}$ 的最短线性递推式 $r_{1 \cdots m}$ ，如何求出 $a_{1 \cdots i}$ 的最短线性递推式。
定义 $a_{1 \cdots i-1}$ 的最短线性递推式 $r_{1 \cdots m}$ 为当前递推式，记递推式被更改的次数为 $c$ ，第 $i$ 次更改后的递推式为 $R_i$ ，特别地，定义 $R_0$ 为空，那么当前递推式应当为 $R_c$ 。
记 $\Delta_i=a_i-\sum_{j=1}^m r_j * a_{i-j}$ ，其中 $r_{1 \cdots m}$ 为当前递推式，显然若 $\Delta_i=0$ ，那么当前递推式就是 $a_{1 \cdots i}$ 的最短线性递推式。否则，我们认为 $R_c$ 在 $a_i$ 处出错了，定义 $\mathrm{fail}_i$ 为 $R_i$ 最早的出错位置，则有 $\mathrm{fail}{ }_c=i$ 。
若 $c=0$ ，这意味着 $a_i$ 是序列中第一个非零元素，我们可以令 $R_{c+1}=\{0,0,0, \ldots, 0\}$ ，即用 $i$ 个 0 填充线性递推式，此时由于不存在 $j$ 使得 $m+1 \leq j \leq i$ ，因此 $R_{c+1}$ 显然为 $a_{1 \cdots i}$ 的线性递推式，并且由于 $a_i$ 是序列中第一个非零元素，不难证明 $R_{c+1}$ 也是 $a_{1 \cdots i}$ 的最短线性递推式。
否则，即 $c>0$ ，考虑 $R_{c-1}$ 出错的位置 fail $_{c-1}$ ，记 $\mathrm{mul}=\frac{\Delta_i}{\Delta_{\text {fail } c-1}}$ 。我们希望得到数列 $R^{\prime}=r_{1 \cdots m^{\prime}}^{\prime}$ ，使得 $\sum_{j=1}^{m^{\prime}} r_j^{\prime} \cdot a_{k-j}=0$ 对于任意 $m^{\prime}+1 \leq k \leq i-1$ 均成立，并且 $\sum_{j=1}^{m^{\prime}} r_j^{\prime} \cdot a_{i-j}=\Delta_i$ 。如果能够找到这样的数列 $R^{\prime}$ ，那么令 $R_{c+1}=R_c+R^{\prime}$ 即可（其中+定义为各位分别相加）。
构造数列 $R^{\prime}$ 如下：$\left\{0,0,0, \ldots, 0, \mathrm{mul},-\mathrm{mul} \cdot R_{c-1}\right\}$ ，即填充 $i-\mathrm{fail}_{c-1}-1$ 个零，然后将数列 $\left\{1,-R_{c-1}\right\}$ 的 mul 倍放在后面。容易验证其合法性，故令 $R_{c+1}=R_c+R^{\prime}$ 即可。在最坏情况下，我们可能需要对数列进行 $O(n)$ 次修改，因此该算法的时间复杂度为 $O\left(n^2\right)$

---

然后还有大佬的实数域上的算法code:

```c
#include <bits/stdc++.h>
#define pii pair<int, int>
#define mp(x, y) make_pair(x, y)
#define pb push_back
#define eb emplace_back
#define fi first
#define se second
#define int long long
#define mem(x, v) memset(x, v, sizeof(x))
#define mcpy(x, y, n) memcpy(x, y, sizeof(int) * (n))
#define lob lower_bound
#define upb upper_bound
using namespace std;

inline int read() {
	int x = 0, w = 1;char ch = getchar();
	while (ch > '9' || ch < '0') { if (ch == '-')w = -1;ch = getchar(); }
	while (ch >= '0' && ch <= '9') x = x * 10 + ch - '0', ch = getchar();
	return x * w;
}

const int MN = 2e3 + 5;
const int Mod = 998244353;
const int inf = 1e9;
const double eps = 1e-8;

inline int qPow(int a, int b = Mod - 2, int ret = 1) {
    while (b) {
        if (b & 1) ret = ret * a % Mod;
        a = a * a % Mod, b >>= 1;
    }
    return ret;
}

#define dbg

int N, c, fail[MN];
double val[MN], delta[MN];
vector <double> ans[MN];

signed main(void) {
    N = read();
    for (int i = 1; i <= N; i++) 
        scanf("%lf", &val[i]);
    for (int i = 1; i <= N; i++) {
        double tmp = val[i];
        for (int j = 0; j < ans[c].size(); j++) 
            tmp -= ans[c][j] * val[i - j - 1];
        delta[i] = tmp;
        if (fabs(tmp) <= eps) continue;
        fail[c] = i;
        if (!c) {
            ans[++c].resize(i);
            continue;
        }
        double mul = delta[i] / delta[fail[c - 1]];
        ++c, ans[c].resize(i - fail[c - 2] - 1);
        ans[c].pb(mul);
        for (int j = 0; j < ans[c - 2].size(); j++)
            ans[c].pb(ans[c - 2][j] * -mul);
        if (ans[c].size() < ans[c - 1].size()) ans[c].resize(ans[c - 1].size());
        for (int j = 0; j < ans[c - 1].size(); j++)
            ans[c][j] += ans[c - 1][j];
    }
    for (int i = 0; i < ans[c].size(); i++)
        printf("%.lf ", ans[c][i]);
    return 0;
}
```

### 调库

说了这么多，总之sagemath可以一把梭就对了！

来个🌰尝尝鲜：

#### imaginaryCTF round53-maskLFSR

> task.py

```python
from os import urandom
import matplotlib.pyplot as plt

flag = b'the flag is ictf{REDACTED}'

class lsfr:
    def __init__(self):
        self.state = int.from_bytes(urandom(8),'big')
        self.mask_1 = int.from_bytes(urandom(8),'big')
        self.mask_2 = int.from_bytes(urandom(8),'big')
    def randbit(self):
        b_1 = bin(self.state & self.mask_1).count('1')
        b_2 = bin(self.state & self.mask_2).count('1')
        output = (b_1 & 1) ^ (self.state & 1)
        self.state = (self.state >> 1) + ((b_2 & 1) << 63)
        return output 

def bits_to_bytes(bits):
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        byte_array.append(byte)
    return byte_array


L = lsfr()

random_bytes = bits_to_bytes([L.randbit() for _ in range(8 * len(flag))])
encrypted_flag = bytes(a ^ b for a, b in zip(random_bytes, flag))
print(f'encrypted_flag = {encrypted_flag}')
```

记初始状态为$\vec{state}=(s_0,s_1,\cdots,s_{63})$,那么output的每一个bit都是${s_i}$的线性组合而已，因为${s_i}$存在线性递推关系，所以可以知道最终的${out_i}$也应该存在线性递推关系，其阶数不超过64。这就说明output还是一个LFSR，而给出的输出也足够长，直接调库一把梭：

> exp

```python
#!/usr/local/bin/sage
from sage.matrix.berlekamp_massey import berlekamp_massey

F = GF(2)

def bytes_to_bits(byte_array):
    bits = []
    for byte in byte_array:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        byte_array.append(byte)
    return byte_array



with open("out.txt", 'r', encoding='utf-8') as file:
    exec(file.read())
pt =   b'the flag is ictf'
encrypted_flag_bits = bytes_to_bits(encrypted_flag)



A = bytes_to_bits([a ^^ b for a,b in zip(encrypted_flag[:128],pt)])

minimal_poly = berlekamp_massey([F(i) for i in A])
V = vector(F,minimal_poly.list()[:-1])
l = len(V)

for i in range(128,len(encrypted_flag_bits)):
    prev = vector(F,A[-l:])
    A.append(int(V.dot_product(prev)))

decrypted_flag = bytes([a ^^ b for a,b in zip(encrypted_flag,bits_to_bytes(A))])

print(decrypted_flag)
```

#### imaginaryCTF round53-maskLFSR2

> task.py

```python
from os import urandom
from secrets import randbelow,choice
import string

message = 'ictf{REDACTED}'
class lsfr:
    def __init__(self):
        self.state = int.from_bytes(urandom(8),'big')
        self.mask_1 = int.from_bytes(urandom(8),'big')
        self.mask_2 = int.from_bytes(urandom(8),'big')
        
        
    def randbit(self):
        b_1 = bin(self.state & self.mask_1).count('1')
        b_2 = bin(self.state & self.mask_2).count('1')
        output = (b_1 & 1) ^ (self.state & 1)
        self.state = (self.state >> 1) + ((b_2 & 1) << 63)
        return output

class lsfr2:
    def __init__(self):
        self.lsfr_1 = lsfr()
        self.lsfr_2 = lsfr()
        
    def randbit(self):
        output = self.lsfr_1.randbit() ^ self.lsfr_2.randbit()
        return output

    
    
    
def bytes_to_bits(byte_array):
    bits = []
    for byte in byte_array:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        byte_array.append(byte)
    return byte_array



def pad(M,n = 256):
    N = n - len(M)
    l = ''.join(choice(string.printable.strip()) for _ in range(randbelow(N)))
    r = ''.join(choice(string.printable.strip()) for _ in range(N - len(l)))
    return l + M + r




L = lsfr2()
flag = pad(message).encode()


random_bytes = bits_to_bytes([L.randbit() for _ in range(8 * len(flag))])
encrypted_flag = bytes(a ^ b for a, b in zip(random_bytes, flag))

print(f'encrypted_flag = {encrypted_flag}')
print(f'gift = {flag[:16]}')

```

类似上一题，还是可以推知output是LFSR，只不过这次阶数大概在128左右，输出有点不够用了。不过想想，因为所有字符都是printable，所以每个字符的MSB一定是0。这意味着从密文中每8bit取1bit就能得到LFSR的间断输出。如果把output这个LFSR的状态转移矩阵记作$A$，那么每8bit取1bit的间断输出对应的状态转移矩阵是$A^8$。$A^8$的minimal polynomial整除$A$的minimal polynomial，而$A$的minimal polynomial阶数又不超过128,所以小爆一下就好了。

> exp

```python
#!/usr/local/bin/sage
from sage.matrix.berlekamp_massey import berlekamp_massey
import re

F = GF(2)

def bytes_to_bits(byte_array):
    bits = []
    for byte in byte_array:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits

def bits_to_bytes(bits):
    byte_array = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for bit in bits[i:i+8]:
            byte = (byte << 1) | bit
        byte_array.append(byte)
    return byte_array

def crack_lfsr(V,initial):
    l = len(V)
    bits = initial[:]
    for i in range(len(bits),len(encrypted_flag_bits)):
        prev = vector(F,bits[-l:])
        bits.append(int(V.dot_product(prev)))
    decrypted_flag = bytes([a ^^ b for a,b in zip(encrypted_flag,bits_to_bytes(bits))])
    return decrypted_flag
    
encrypted_flag = b'\x12\xba\x0b\x94\x19$\xceQD\x90\x9a\xc4Y\xb1FB\\4\x0f\xf0\xf8\xf5\xbe\x8c\x90v /c1\x8a}\\~\\\xa1&\xb4\x10\xc8\xd2\x8cn\xf9\x0c/\xff\xad\tW\x0cG\xeb\x8d\xd9\xdb\xf6\x9b\x03{\xb0[\xc7=<\x92d \x85\x9ew\xbaq\xa7\xc9\xc7\xe7\xb0c\xb2\x92\xfch\xa9H\x8c\x83\x9b\xb9\x19\xa2\x9c\xf5*\x00\xdc`\xc4\xe25e\t?\nyp\\j5 \xbfm\xe5W\xfa\xc8\xd4\x8d\xba5\xb2\xf5\xc3\xc6\x18[\xeb\xe9"\xd3\xfb\xe4\x93\x9fy\xed\xc6\x1bxtP\xca\x99\xbfR\xe9\xf1\xffX\x1b#\xe2\xa8\xbb2b9C\x8d\xe3\x83\xc2\xc4\x93\x03\xb2\xba\xebz\x9e\xbd-\x9a\xf0I/\xd6z\x07\x18\x9d\x07Oy\x91\xb3\xd9\xf9eT\xd9\x06|\x86\x8c\xec\x865\xf1\xb7_\xfc\xbec\x14\xb4\x19O\xbbN\xee\x81\x8e\xb4\xe3e\x04\xc5\xf3h\x00i\xb2\xde\x1ba\x88\x8f\x9f\xdcN)\n\xf7l?X\xe1 \x86\xc5ruLj*r\x0ck\xebj8\xf4\xd4Z\xe5'
gift = b'9DXBZY3[Wj.G^=HN'



first_16 = bytes_to_bits([a ^^ b for a,b in zip(encrypted_flag[:16],gift)])

encrypted_flag_bits = bytes_to_bits(encrypted_flag)
R.<x> = PolynomialRing(F)

B = [encrypted_flag_bits[8*i] for i in range(len(encrypted_flag_bits) // 8)]
minimal_poly_factor = berlekamp_massey([F(i) for i in B])
polys = list(R.polynomials(max_degree=128-minimal_poly_factor.degree()))[1:]

for poly in polys:
    candidate_annihilating_polynomial = minimal_poly_factor * poly
    V = vector(F,candidate_annihilating_polynomial.list()[:-1])
    possible = crack_lfsr(V,first_16)
    try:
        decoded = possible.decode('utf-8')
        matches = re.findall(r'ictf\{.*\}', decoded)
        if (len(matches) != 0):
            print(f'Found likely flag: {matches}')
            break
    except:
        continue
```

# 不存在线性递推关系

如果不存在线性递推关系，基本上跟LFSR的关系也就不大了。之所以还是放在LFSR的blog里，主要还是因为CTF中很容易遇到利用多个LFSR的组合构造不存在线性递推关系的输出的例子。当然，第一思路还是想办法构造方程求解，这里我们引入另一种代数攻击手法：代数免疫攻击。

## 代数免疫度

给定一个布尔函数$f$，它的代数免疫度是满足$fg=0$的度数最小的$g$的度。这样的$g$称为$f$的annihilator。

annihilator有个好处，就是当f(x)=1时，g(x)一定为0。如果g的度比f低，那么我们求解输入参数所需要构造的方程数量就会少一点；比方说，如果g的度是1，那么我们只需要构造线性方程；如果g的度是2,那么我们所需的方程数大概也就是$n+\tbinom{n}{2}$(单项式的数量),$n$为未知数数量。

来看个🌰：

### modified from HITCON CTF 2024 Qual-Hyper512

> task

```python
import secrets
from hashlib import shake_256

MASK1 = 0x77E3816DD9E3627340D7EE76204ED9F9
MASK2 = 0x512E5CEC93B9AE8D6E28E2AB78B8432B


class LFSR:
    def __init__(self, n: int, key: int, mask: int):
        self.n = n
        self.state = key & ((1 << n) - 1)
        self.mask = mask

    def __call__(self):
        b = self.state & 1
        self.state = (self.state >> 1) | (
            ((self.state & self.mask).bit_count() & 1) << (self.n - 1)
        )
        return b


class Cipher:
    def __init__(self, key):
        self.lfsr1 = LFSR(128, key[0], MASK1)
        self.lfsr2 = LFSR(128, key[1], MASK2)
        self.lfsr3 = LFSR(128, key[0] ^ key[1], MASK2)

    def bit(self):
        x = self.lfsr1()
        y = self.lfsr2() ^ self.lfsr2()
        z = self.lfsr3() ^ self.lfsr3() ^ self.lfsr3()
        return shake_256(str(x + 2 * y + 3 * z + 624).encode()).digest(64)[0] & 1

    def stream(self):
        while True:
            b = 0
            for i in reversed(range(8)):
                b |= self.bit() << i
            yield b

    def encrypt(self, pt: bytes):
        return bytes([x ^ y for x, y in zip(pt, self.stream())])

    def decrypt(self, ct: bytes):
        return self.encrypt(ct)

if __name__ == "__main__":
    with open("flag.txt", "rb") as f:
        flag = f.read().strip()
    key = [secrets.randbits(256), secrets.randbits(256)]
    cipher = Cipher(key)
    gift = cipher.encrypt(b"\x00" * 96)
    print(gift.hex())
    ct = cipher.encrypt(flag)
    print(ct.hex())
```

bit的输出形式很抽象，先来构造真值表看看它究竟长啥样：

```python

from sage.crypto.boolean_function import BooleanFunction
from hashlib import shake_256

truth_table = []
for z in range(2):
    for y in range(2):
        for x in range(2):
            bit = shake_256(str(x + 2 * y + 3 * z + 624).encode()).digest(64)[0] & 1
            truth_table.append(bit)

f = BooleanFunction(truth_table)
fp = f.algebraic_normal_form()
fp
# x0*x1*x2 + x0*x2 + x1 + x2
```

度数为3,直接攻击不大可行。再检查一下annihilator：

```python
imu , g = f.algebraic_immunity(annihilator = True)
assert fp*g == 0
print(f"{imu = }, {g = }")
# imu = 1, g = x1 + x2 + 1
```

度数为1，正适合代数免疫的打法。从[tl2cents大佬那抄一份exp](https://blog.tanglee.top/2024/07/15/HITCON-CTF-2024-Qual-Crypto-Writeup.html)过来:

```python
import os
import json
import signal
from sage.all import *
from itertools import combinations
from tqdm import tqdm
import secrets
MASK1 = int(0x77E3816DD9E3627340D7EE76204ED9F9)
MASK2 = int(0x512E5CEC93B9AE8D6E28E2AB78B8432B)

ct = "..."
enc_flag = "..."
ct = bytes.fromhex(ct)
enc_flag = bytes.fromhex(enc_flag)

    
class LFSRSymbolic:
    def __init__(self, n, key, mask):
        assert len(key) == n, "Error: the key must be of exactly 128 bits."
        self.state = key
        self.mask = mask
        self.n = n
        self.mask_bits = [int(b) for b in bin(self.mask)[2:].zfill(n)]
        
    def update(self):
        s = sum([self.state[i] * self.mask_bits[i] for i in range(self.n)])
        self.state = [s] + self.state[:-1]
        
    def __call__(self):
        b = self.state[-1]
        self.update()
        return b  
class CipherSymbolic:
    def __init__(self, key: list):
        self.lfsr1 = LFSRSymbolic(128, key[-128:], MASK1)
        self.lfsr2 = LFSRSymbolic(128, key[-256:-128], MASK2)
        self.lfsr3 = LFSRSymbolic(128, [a - b for a, b in zip(key[-128:],key[-256:-128])], MASK2)
        
    def filter_polynomial(self, x0, x1, x2, x3):
        # x0*x1*x2 + x0*x2 + x1 + x2
        return x0*x1*x2 + x0*x2 + x1 + x2

    def bit(self):
        x,y,z = self.get_xyz()
        return self.filter_polynomial(x, y, z)
    
    def get_xyz(self):
        x = self.lfsr1()
        y = self.lfsr2() + self.lfsr2()
        z = self.lfsr3() + self.lfsr3() + self.lfsr3()
        return x,y,z
    
    def get_yz(self):
        y = self.lfsr2() + self.lfsr2()
        z = self.lfsr3() + self.lfsr3() + self.lfsr3()
        return y,z
    
    def stream(self, n):
        return [self.bit() for _ in range(n)]
            
    def xor(self, a, b):
        return [x + y for x, y in zip(a, b)]

    def encrypt(self, pt: bytes):
        pt_bits = [int(b) for b in bin(int.from_bytes(pt, 'big'))[2:].zfill(8 * len(pt))]
        key_stream = self.stream(8 * len(pt))
        return self.xor(pt_bits, key_stream)
    
key = secrets.randbits(256)
key_bits = [int(i) for i in bin(key)[2:].zfill(256)]
br256 = BooleanPolynomialRing(256, [f"x{i}" for i in range(256)])
key_sym = list(br256.gens())
print(len(key_sym))
# cipher = Cipher(key)
cipher_sym = CipherSymbolic(key_sym)

pt = b"\x00" * 128
ct_bits = [int(b) for b in bin(int.from_bytes(ct, 'big'))[2:].zfill(8 * len(ct))]
print(ct_bits.count(1))

# check if yz_list.obj exists
if os.path.exists("./yz_list.obj.sobj"):
    yz_list = load("./yz_list.obj.sobj")
else:
    yz_list = []
    for i in tqdm(range(len(pt) * 8)):
        yz_list.append(cipher_sym.get_yz())
    save(yz_list, "./yz_list.obj")



eqs = []
for i, bit in enumerate(ct_bits):
    if bit == 1:
        eqs.append(yz_list[i][0] + yz_list[i][1] + 1)

def all_monomials(x1s, x2s):
    d1_monos = x1s[:] + x2s[:]
    return [1] + d1_monos

def fast_coef_mat(monos, polys, br_ring):
    mono_to_index = {}
    for i, mono in enumerate(monos):
        mono_to_index[br_ring(mono)] = i
    # mat = matrix(GF(2), len(polys), len(monos))
    mat = [[0] * len(monos) for i in range(len(polys))]
    for i, f in tqdm(list(enumerate(polys))):
        for mono in f:
            # mat[i,mono_to_index[mono]] = 1
            mat[i][mono_to_index[mono]] = 1
    return mat
x2s = key_sym[128:256]
x1s = key_sym[:128]
monos = all_monomials(list(x1s), list(x2s))
print(f"[+] total equations {len(eqs)}")
print(f"[+] total monomials {len(monos)}")

mat = fast_coef_mat(monos, eqs, br256)
mat = matrix(GF(2), mat)
B = vector(GF(2),[1 for j in range(len(eqs))])
mat = mat[:, 1:]
print(f"[+] {mat.dimensions() = }, {mat.rank() = }")
try:
    sol = mat.solve_right(B)
    print(f"[+] solution found")
    print(f"[+] solution: {sol}")
    ker = mat.right_kernel()
    for v in ker.basis():
        print(f"[+] kernel vector: {v}")
    # break
except:
    print(f"[+] no solution")
```

最后这里不满秩，需要再手动处理一下拿到最终的key。

嗯，就酱。