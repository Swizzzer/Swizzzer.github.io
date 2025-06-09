---
title: NoisyCRT
tags: ["Crypto", "Lattice"]
category: Notes
description: "带噪声的CRT也不是不能恢复"
published: 2025-02-14
---

CRT一般是在已知

$$x\equiv{a_1}\pmod{p_1}$$
$$x\equiv{a_2}\pmod{p_2}$$
$$\vdots$$
$$x\equiv{a_m}\pmod{p_m}$$
时用于求
$$x\equiv{a}\pmod{\prod{p_i}}$$
的解的方法。但是，如果已知的条件并非一一对应的$(a_i,p_i)$，而是经过了shuffle的呢？

Noisy CRT就是为了解决此种情况而提出的（一次shuffle就可以看作一次noise的掺入不是吗），这一点是基于一个观察：

我们在正常的CRT求解时，其实很像是在每个$\mathbb{Z}mod(N_i)$里找了一个basis，最终用这些basis去线性表示我们最终的解。具体地来说，是这么一回事：

先取 $T_i$ 符合
$$
\begin{array}{ll}
T_i \equiv 1 & \left(\bmod p_i\right) \\
T_i \equiv 0 & \left(\bmod p_{j \neq i}\right)
\end{array}
$$

那么对于一个 $x \equiv a_i\left(\bmod p_i\right)$ 的系統，可以得出解为 $x \equiv \sum a_i T_i\left(\bmod \prod p_i\right)$ 。

默认情况下我们是用直接的CRT求T的，但是在noisy CRT情况下，因为经过了shuffle，所以我们需要再把$T_i$摊开一下：
$$x\equiv \sum_{i=1}\sum_{j=1}\delta_{i,j} r_{i,j}a_i\pmod{\prod{p_i}}$$
其中$r_{i,j}$是正常CRT下我们求出的T，$\delta$在r和a对应时取1，不对应时取0。这时我们构造格
$$\left(\begin{array}{ccccc}
\prod{p_i} & 0 & \ldots & \ldots & 0 \\
r_{1,1} a_1 & B & 0 & \ldots & 0 \\
r_{1,2} a_1 & 0 & B & \ddots & \vdots \\
\vdots & \vdots & \ddots & \ddots & 0 \\
r_{m, m} a_n & 0 & \ldots & 0 & B
\end{array}\right)$$
那么$(x,\overrightarrow{\delta})$就在这个格子里,适当选取B优化我们的格子就很有可能规约出我们想要的x。

> 有线性组合的地方就有格！

以上的情况实际上是shuffle了以下CRT矩阵的列(并且是nx1大小的矩阵):
$$\left(\begin{array}{ccccc}
N_1\bmod{p_1}&N_2\bmod{p_1}&\cdots&N_m\bmod{p_1}\\
N_1\bmod{p_2}&N_2\bmod{p_2}&\cdots&\\
\vdots\\
N_1\bmod{p_n}&\cdots& & N_m\bmod{p_n}
\end{array}\right)
$$
这种情况有一个很麻烦的地方——在摊平CRT矩阵时，每一行具体要乘上的$r_i$是不确定的。
一般情况下我们遇见的noisy CRT是对以上CRT矩阵的行进行shuffle，这样每一行需要乘上的是确定的，那么摊平后LLL就变得更容易了。

不管怎么说，最终需要的格子都很大，所以规约的时候一般都需要flatter去加速。


