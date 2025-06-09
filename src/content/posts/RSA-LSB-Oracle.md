---
title: RSA LSB Oracle Attack
tags: ["Crypto", "RSA"]
category: Notes
published: 2024-11-29
---
翻看[crypto attacks](https://github.com/jvdsn/crypto-attacks)时发现的一种攻击，稍微研究了下。

原版脚本只支持模2情况下的oracle，这里我们考虑一个模k的oracle。

给定一份密文c，允许我们每次选取密文oracle，返回的值是这个密文用同样的密钥解密后模k的结果——

$$Input:c'$$

$$Output:oracle(c')=c'^{d}\%k,d\ \text{is private key}$$

我们把明文$m$写成k进制展开的形式：

$$m=a_0+a_1k+a_2k^2+\cdots+a_nk^n$$

首先我们直接把c送回去可以拿到$a_0$。因为返回的结果是模k的，所以下一步应该考虑如何拿$a_1$，这样在k进制下一步步oracle出来所有位。
想拿到$a_1$需要保证送进去的$c'$解密后$a_1$从一次项挪到常数项里，基本的思路就是在c上乘个什么让$c'^d$里出现个$k^{-1}$的项，把$a_1$上的k给消去。设乘的这个数字为x，那么最理想的情况下，我们希望它满足：
$$(x*c)^d=x^d*m\equiv k^{-1}*m$$
而$k^{ed}\equiv{k}\bmod{\varphi(n)}\Rightarrow k^{-1}\equiv k^{-ed}\bmod{\varphi(n)}$，所以取x为$k^{-e}$即可满足要求。
这样拿到的oracle结果在$\mathbb{Z}mod(k)$上减去$a_0*k^{-e}$之后即是$a_1$，后面的各项同理，不再赘述。


>一份简要的poc：

```python
c = 
n = 
e = 
counter = 0
plaintext = 0
i = 0
while True:
    inv = inverse(NUM_MOD,n) # pow(NUM_MOD,-1)
    c_ = (c * pow(inv,e*i,n)) % n
    p = Oracle(c_) # the Oracle function implemented in the problem
    print(p)
    a_ = (p - (a*inv) % n) % NUM_MOD
    print(a_)
    if a_ == 0:
        counter += 1
        if counter == 32: # reach the end
            break
    a = a*inv + a_
    plaintext = NUM_MOD**i*a_ + plaintext
print(long_to_bytes(plaintext))
```
