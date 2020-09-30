# $ DES $ 算法实现

### **【算法原理概述】**

&emsp;&emsp;$ DES $ 是一种对称块加密算法，采用 $64$ 位密钥（实际有效密钥长度为 $56$ 位），加密时将明文分割成 $64$ 位一组的块作为输入，经过一系列的计算输出同样长度的密文；只有持有加密密钥才能解密密文，解密时同样将密文分割成 $64$ 位一组的块作为输入，经过计算还原得到明文。<br/><br/>

### **【总体结构】**

#### $DES$ 算法信息空间：
- 明文分组结构：$M = m_{1}m_{2}...m_{64}, m_{i}\in\{0,1\}, i = 1..64$
- 密文分组结构：$C = c_{1}c_{2}...c_{64}, c_{i}\in\{0,1\}, i = 1..64$
- 密钥结构：$K = k_{1}k_{2}...k_{64}$，其中 $k_{8}, k_{16}, k_{24}, k_{32}, k_{40}, k_{48}, k_{56}, k_{64}$ 为奇偶校验位
- 原始明文消息按 $PKCS\#5(RFC 8018)$ 规范进行字节填充：
  - 原始明文消息最厚的分组不够 $8$ 个字节时，在末尾填满同样取值的字节，为填充的字节数目
  - 原始明文消息刚好分组完全时，在明文末尾额外填充 $8$ 个字节，每个字节取值都为 $08$

<br/>

#### $DES$ 算法加密/解密过程：
- 输入 $64$ 位数据
- 初始置换 $IP$
- $16$ 轮迭代 $T$
  - 加密过程：输入 $64$ 位明文 $M$ 时，子密钥按($K_{1}K_{2}...K_{16}$) 次序调度，得到迭代变换 $T_{1} · T_{2} ·...· T_{16}$
  - 解密过程：输入 $64$ 位密文 $C$ 时，子密钥按($K_{16}K_{15}...K_{1}$) 次序调度，得到迭代变换 $T_{16} · T_{15} ·...· T_{1}$
- 交换置换 $W$
- 逆置换 $IP^{-1}$
- 输出 $64$ 位数据

<br/>

### **【模块分解】**

### &ensp;&ensp;**des.c**

- 输入 $64$ 位数据

  从控制台或文件中读入数据，以 $64$ 位为分组长度作为算法的输入。

- 初始置换 $IP$

  给定 $64$ 位明文块 $M$，通过一个固定的初始置换 $IP$ 重排 $M$ 中的二进制位，得到二进制串 $M_{0} = IP(M) = L_{0}R_{0}$，这里 $L_{0}$ 和 $R_{0}$ 分别是 $M_{0}$ 的前 $32$ 位和后 $32$ 位。<br/>
  $IP$ 置换后的下标编号序列如图：<br/>
  ![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@v1.5.0/image/des-003.png)<br/>

- $16$ 轮迭代 $T$
  
  ![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@master/image/des-015.jpg)<br/>
  由 $IP$ 置换得到 $L_{0}$ 和 $R_{0}$ 后，根据 $L_{i} = R_{i-1}, R_{i} = L_{i-1} \oplus f(R_{i-1}, K_{i}), i = 1..16$迭代16轮，最终得到 $L_{16}R_{16}$。其中：
  - $K_{i}$ 为由密钥 $K$ 生成的 $48$ 位子密钥。根据给定的 $64$ 位密钥 $K$，可以生成 $16$ 个 $48$ 位的子密钥 $K_{1}$-$K_{16}$
    - 对 $K$ 的 $56$ 个非校验位进行 $PC$-$1$ 置换，得到 $C_{0}D_{0}$（$C_{0}$ 和 $D_{0}$ 分别为 $PC$-$1$ 置换结果的前 $28$ 位和后 $28$ 位组成）<br/>
    $PC$-$1$ 置换表如图：<br/>
    ![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@v1.5.0/image/des-004.png)<br/>
    - 计算 $C_{i} = LS_{i}(C_{i-1})$ 和 $D_{i} = LS_{i}(D_{i-1})$
      - 当 $i = 1, 2, 9, 16$ 时，$LS_{i}(A)$ 表示将二进制串 $A$ 循环左移一个位置；否则循环左移两个位置
    - 对 $56$ 位的 $C_{i}D_{i}$ 压缩后进行 $PC$-$2$ 置换，得到 $48$ 位的 $K_{i}$<br/>
    $PC$-$2$ 置换表如图：<br/>
    ![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@v1.5.0/image/des-009.png)<br/>
    - 计算得到所有的 $K_{i}$
  - $f(R_{i-1}, K_{i})$ 为输出 $32$ 位的 $Feistel$ 轮函数
    - 将 $32$ 位的串 $R_{i-1}$ 作 $E$-扩展，得到一个 $48$ 位的串 $E(R_{i-1})$<br/>
      $E$-扩展 $32$ 位二进制串扩展后的下标编号序列如图：<br/>
      ![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@v1.5.0/image/des-005.png)<br/>
    - 将 $E(R_{i-1})$ 和长度为 $48$ 位的子密钥 $K_{i}$ 作 $48$ 位二进制串按位异或运算
    - 将上述按位异或运算得到的结果平均分成 $8$ 个分组，每个分组长度 $6$ 位。各个分组分别经过 $8$ 个不同的 $S$-盒进行 $6-4$ 转换，得到 $8$ 个长度分别为 $4$ 位的分组
      - 对于分组 $a_{i}$，使用 $S_{i}(i = 1..8)$
      - 假设 $S_{i}$ 的 $6$ 位二进制输入为 $b_{1}b_{2}b_{3}b_{4}b_{5}b_{6}$，则由 $n = {(b_{1}b_{6})}_{10}$ 确定行号，由 $m = {(b_{2}b_{3}b_{4}b_{5})}_{10}$ 确定列号，$S_{i}[n, m]$ 元素的值的二进制形式即为所要的 $S_{i}$ 的输出<br/>
      $S$-盒 $S_{1}-S_{8}$ 如图：<br/>
      ![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@v1.5.0/image/des-006.png)<br/>
      ![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@v1.5.0/image/des-007.png)<br/>
    - 将上述得到的分组结果顺序连接得到长度为 $32$ 位的串 
    - 将上述连接得到的串经过 $P$-置换，得到的结果作为轮函数 $f(R_{i-1}, K_{i})$ 的最终 $32$ 位输出<br/>
      $32$ 位二进制串 $P$-置换后的下标编号序列如图：<br/>
      ![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@v1.5.0/image/des-008.png)<br/>

- 将 $16$ 轮迭代得到的 $L_{16}R_{16}$ 进行左右交换置换，得到 $R_{16}L_{16}$
- 对交换置换输出的二进制串 $R_{16}L_{16}$使用逆置换 $IP_{-1}$ 得到密文 $C$，即 $C = IP_{-1}(R_{16}L_{16})$<br/>
  $IP_{-1}$ 置换后的下标编号序列如图：<br/>
  ![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@v1.5.0/image/des-010.png)<br/>
- 输出 $64$ 位数据<br/>
  将 $64$ 位加密的密文/解密的明文作为算法的输出。
<br/>

### &ensp;&ensp;**main.c**

- 获得密钥
  - 如果当前程序目录存有存放密钥的文件，则读入密钥 $K$，否则生成一个随机密钥（满足奇偶校验条件）作为密钥 $K$，并将其写入一个新文件中。
- 读入数据
  - 打开待加密/解密的文件，以 $64$ 位为单位长度读入数据。若读入数据为明文，则需要进行字节填充；若读入数据为密文，则需要将数据尾部 $n$ 个字节删除，$n$ 的值由密文数据最后一个字节确定。
- 写入数据
  - 将加密后的密文/解密后的明文写入一个新文件中，加密后的密文长度一定为 $8$ 字节的整数倍，解密后的明文与原始明文一致。

<br/>

### **【数据结构设计】**

&emsp;&emsp;该算法实现无自定义数据结构，实现过程所涉及的主要数据结构如下：
- $48$ 位子密钥 $K_{1}$-$K_{16}$: ``uint64_t[]``
- $IP, IP^{-1}, PC-1, PC-2, P, E, S_{1}-S_{8}$: ``int[]``
- 明文块/密文块: ``uint8_t[]``

<br/>

### **【源代码】**

**注：** 所有代码均已同步到 github[🔗传送门]()

程序文件结构如下：

![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@master/image/des-019.png)

``des.h``
```C
#ifndef _DES_
#define _DES_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>

#define UNIT32 0x00000001
#define UNIT64 0x0000000000000001
#define GET_INT28 0x000000000fffffff
#define GET_INT32 0x00000000ffffffff

/*------------DES算法相关数据------------*/

static int IP[64] = {
    58, 50, 42, 34, 26, 18, 10,  2, 
    60, 52, 44, 36, 28, 20, 12,  4, 
    62, 54, 46, 38, 30, 22, 14,  6, 
    64, 56, 48, 40, 32, 24, 16,  8, 
    57, 49, 41, 33, 25, 17,  9,  1, 
    59, 51, 43, 35, 27, 19, 11,  3, 
    61, 53, 45, 37, 29, 21, 13,  5, 
    63, 55, 47, 39, 31, 23, 15,  7
};


static int IP_INV[64] = {
    40,  8, 48, 16, 56, 24, 64, 32, 
    39,  7, 47, 15, 55, 23, 63, 31, 
    38,  6, 46, 14, 54, 22, 62, 30, 
    37,  5, 45, 13, 53, 21, 61, 29, 
    36,  4, 44, 12, 52, 20, 60, 28, 
    35,  3, 43, 11, 51, 19, 59, 27, 
    34,  2, 42, 10, 50, 18, 58, 26, 
    33,  1, 41,  9, 49, 17, 57, 25
};

static int PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,    
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

static int PC2[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static int E[48] = {
    32,  1,  2,  3,  4,  5,  
     4,  5,  6,  7,  8,  9,  
     8,  9, 10, 11, 12, 13, 
    12, 13, 14, 15, 16, 17, 
    16, 17, 18, 19, 20, 21, 
    20, 21, 22, 23, 24, 25, 
    24, 25, 26, 27, 28, 29, 
    28, 29, 30, 31, 32,  1
};

static int S[8][64] = {
{
    /* S1 */
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,  
     0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,  
     4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0, 
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
},
{
    /* S2 */
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,  
     3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,  
     0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15, 
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
},
{
    /* S3 */
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,  
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,  
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
     1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
},
{
    /* S4 */
     7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,  
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,  
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
     3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
},
{
    /* S5 */
     2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9, 
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6, 
     4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14, 
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
},
{
    /* S6 */
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
     9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
     4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
},
{
    /* S7 */
     4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
     1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
     6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
},
{
    /* S8 */
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
     1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
     7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
     2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
}};

static int P[32] = {
    16,  7, 20, 21, 
    29, 12, 28, 17, 
     1, 15, 23, 26, 
     5, 18, 31, 10, 
     2,  8, 24, 14, 
    32, 27,  3,  9, 
    19, 13, 30,  6, 
    22, 11,  4, 25
};

/*------------核心函数------------*/

/* 16个48位子密钥*/
static uint64_t subkey[16] = {0};

/* 初始置换IP */
uint64_t initial_displace(uint64_t M);

/* 从密钥K生成16个子密钥 */
void generate_subkey(uint64_t K);

/* feistel轮函数*/
uint64_t feistel(int index, uint32_t R);

/* 迭代T */
uint64_t iteration(uint32_t L0, uint32_t R0, int flag);

/* 交换置换W */
uint64_t swap_displace(uint64_t LR);

/* IP逆置换 */
uint64_t inverse_displace(uint64_t W);

/* des算法加/解密 */
uint64_t des(uint64_t input, uint64_t K, int flag);

/*------------辅助函数------------*/

/* 从明文块/密文块得到64位明文/密文 */
uint64_t to_uint64_t(uint8_t buf[]);

/* 将64位明文/密文分割为8位一组的明文块/密文快 */
void to_uint8_t(uint64_t output, uint8_t * buf);

/* 计算奇偶校验位 */
int parity_count(uint8_t arg);

/* 生成一个符合奇偶校验的随机密钥 */
uint64_t generate_key();

/* S盒选择 */
uint8_t S_transform(int index, uint8_t input);

#endif
```
<br/>

``des.c``
```C
#include "des.h"

const int LS[16] = {1,  1,  2,  2,  2,  2,  2,  2,  1,  2,  2,  2,  2,  2,  2,  1};

uint64_t initial_displace(uint64_t M) {
	uint64_t M0 = 0;
	for (int i = 0; i < 64; ++i) {
		M0 = M0 << 1;
		M0 |= (M >> (64 - IP[i])) & UNIT64;
	}
	return M0;
}

void generate_subkey(uint64_t K) { // OK!
	uint64_t pre_K = 0;
	uint32_t pre_C = 0, pre_D = 0;
	uint32_t cur_C, cur_D;

	for (int i = 0; i < 56; ++i){
		pre_K = pre_K << 1;
		pre_K |= (K >> (64 - PC1[i])) & UNIT64;
	}
	pre_C = (uint32_t)((pre_K >> 28) & GET_INT28); //C0
	pre_D = (uint32_t)(pre_K & GET_INT28); //D0

	for (int i = 0; i < 16; ++i) {
		int n = LS[i];
		cur_C = ((pre_C << n) & 0x0fffffff)|(pre_C >> (28-n)); //循环左移 n 位
		cur_D = ((pre_D << n) & 0x0fffffff)|(pre_D >> (28-n));

		uint64_t CD = 0;
		CD |= cur_C;
		CD <<= 28;
		CD |= cur_D;

		subkey[i] = 0;
		for (int j = 0; j < 48; ++j) {
			subkey[i] = subkey[i] << 1;
			subkey[i] |= (CD >> (56 - PC2[j])) & UNIT64;
		}

		pre_C = cur_C;
		pre_D = cur_D;
	}
}

uint8_t S_transform(int index, uint8_t input) {	
	int col = (int)((input >> 1) & 0b00001111);
	int row = ((input >> 5) << 1) | (input & 0b00000001);
	return (uint8_t)(S[index][row*16+col]);
}

uint64_t feistel(int index, uint32_t R) { // OK!
	uint64_t expanded = 0; //48 bits
	for (int i = 0; i < 48; ++i) {
		expanded = expanded << 1;
		expanded |= (R >> (32 - E[i])) & UNIT64;
	}

	expanded ^= subkey[index];

	uint32_t P_input = 0;
	/* S box */
	for (int i = 0; i < 8; ++i) {
		uint8_t S_input = (uint8_t)(expanded & 0x000000000000003f); //6 bits
		expanded = expanded >> 6;
		P_input |= ((uint32_t)S_transform(8-i-1, S_input)) << (4*i); // lowest 8 bits with S8
	}

	uint32_t P_output = 0;
	for (int i = 0; i < 32; ++i) {
		P_output = P_output << 1;
		P_output |= (P_input >> (32 - P[i])) & UNIT32;// 32 or 64?
	}
	return P_output;
}

uint64_t iteration(uint32_t L0, uint32_t R0, int flag) { //flag 0 represents encryption, flag 1 represents decryption
	uint32_t pre_L = L0, pre_R = R0;
	uint32_t cur_L, cur_R;
	for (int i = 0; i < 16; ++i){
		cur_L = pre_R;
		if (flag == 0)
			cur_R = pre_L ^ feistel(i, pre_R);
		else 
			cur_R = pre_L ^ feistel(16-i-1, pre_R);

		pre_L = cur_L;
		pre_R = cur_R;
	}
	return ((uint64_t)cur_L << 32) | (uint64_t)cur_R;
}

uint64_t swap_displace(uint64_t LR) {
	uint64_t RL = 0;
	RL |= (LR & GET_INT32);//LR's low 32 bits
	RL = RL << 32;
	LR = LR >> 32;
	RL |= (LR & GET_INT32);//LR's high 32 bits
	return RL;
}

uint64_t inverse_displace(uint64_t W) {
	uint64_t C = 0;
	for (int i = 0; i < 64; ++i) {
		C = C << 1;
		C |= (W >> (64 - IP_INV[i])) & UNIT64;
	}
	return C;
}

uint64_t des(uint64_t input, uint64_t K, int flag) {
    generate_subkey(K);
	uint64_t output = 0;
	output = initial_displace(input); // OK!
	uint32_t L0 = (uint32_t)((output >> 32) & GET_INT32), R0 = output & GET_INT32; // OK!
	output = iteration(L0, R0, flag); // OK!
	output = swap_displace(output); // OK!
	output = inverse_displace(output); // OK!
	return output;
}

uint64_t to_uint64_t(uint8_t buf[]) {
	uint64_t res = 0;
	for (int i = 0; i < 8; ++i) {
		res = res << 8;
		res |= (uint64_t)(buf[i] & 0xff);
	}
	return res;
}

void to_uint8_t(uint64_t output, uint8_t * buf) {
	for (int i = 7; i >= 0; --i) {
		buf[i] = output & 0xff;
		output = output >> 8;
	}
	return;
}

int parity_count(uint8_t arg) {
	int count = 0;
	for (int i = 0; i < 8; ++i) {
		if (arg & 0x01)	count++;
		arg = arg >> 1;
	}
	return count;
}

uint64_t generate_key() {
	uint64_t K = 0;
	for (int i = 0; i < 8; ++i) {
		K = K << 8;
		uint8_t _8bits = rand() & 0xfe;
		K |= (uint64_t)(_8bits);
		if (parity_count(_8bits) % 2)	//odd
			K |= (uint64_t)0;
		else							//even
			K |= (uint64_t)1;
	}
	return K;
}
```
<br/>

``main.c``
```C
#include "des.h"

int main(int argc, char *argv[]) { // ./des input.txt output.txt -e
	if ((argc != 4) || (strcmp(argv[3], "-e") != 0 && strcmp(argv[3], "-d") != 0)) {
		printf("Command should be like: ./des [input file][output file][-e | -d]\n");
		return 0;
	}

	FILE *Input = fopen(argv[1], "rb");
	if (!Input) {
		perror(argv[1]);
		return 0;
	}

	FILE *Output = fopen(argv[2], "wb");
	if (!Output) {
		perror(argv[2]);
		return 0;
	}

	/* generate a key*/
	time_t t;
	srand((unsigned) time(&t));
	uint64_t K;

	FILE *Key_file = fopen("key.txt", "rb");
	if (!Key_file) {
		Key_file = fopen("key.txt", "wb");
		K = generate_key();
		uint8_t kbuf[8];
		to_uint8_t(K, kbuf);
		fwrite(kbuf, sizeof(uint8_t), 8, Key_file);
	}
	else {
		uint8_t kbuf[8];
		fread(kbuf, sizeof(uint8_t), 8, Key_file);
		K = to_uint64_t(kbuf);
	}
	fclose(Key_file);

	/* if encrypt */
	if (strcmp(argv[3], "-e") == 0) {
		int rlen = 0;
		while(1) {
			uint8_t rbuf[8];
			rlen = fread(rbuf, sizeof(uint8_t), 8, Input);

			if (rlen < 8 && rlen >= 0) {
				uint8_t filling = (uint8_t)(8-rlen);
				for (int i = rlen; i < 8; ++i) {
					rbuf[i] = filling;
				}
				uint64_t ciphertext = des(to_uint64_t(rbuf), K, 0);
				uint8_t wbuf[8];
				to_uint8_t(ciphertext, wbuf);
				fwrite(wbuf, sizeof(uint8_t), 8, Output);
				break;			
			}
			else if (rlen == 8){
				uint64_t ciphertext = des(to_uint64_t(rbuf), K, 0);
				uint8_t wbuf[8];
				to_uint8_t(ciphertext, wbuf);
				fwrite(wbuf, sizeof(uint8_t), 8, Output);
			}
			else {
				perror("Error");
			}
		}
	}
	/* if decrypt */
	else if (strcmp(argv[3], "-d") == 0) {
		int rlen = 0;
		uint8_t rbuf[8];
		rlen = fread(rbuf, sizeof(uint8_t), 8, Input);
		if (rlen != 8) {
			printf("Error: Something wrong happened when reading the ciphertext.\n");
			return 0;
		}
		uint64_t decipher = des(to_uint64_t(rbuf), K, 1);
		uint8_t wbuf[8];
		to_uint8_t(decipher, wbuf);
		int num = 8 - (int)(wbuf[rlen-1]);

		while(1) {
			rlen = fread(rbuf, sizeof(uint8_t), 8, Input);
			if (rlen == 0) {
				fwrite(wbuf, sizeof(uint8_t), num, Output);
				break;
			}
			else if (rlen == 8) {
				fwrite(wbuf, sizeof(uint8_t), 8, Output);
				decipher = des(to_uint64_t(rbuf), K, 1);
				to_uint8_t(decipher, wbuf);
				num = 8 - (int)(wbuf[rlen-1]);
			}
			else {
				printf("Error: Something wrong happened when reading the ciphertext.\n");
				return 0;
			}
		}
	}

	fclose(Input);
	fclose(Output);
}
```

<br/>

### **【编译运行结果】**

在源代码所在目录下执行 ``make``，得到可执行文件 ``des``，以``./des [input file] [output file] [-e | -d]``的格式执行。

如图，当以字符串 ``01234567abc\n`` 为明文输入时，该明文长度 $96$ 位，得到的密文为 $128$ 位（符合字节填充的要求），再次解密后得到与原始明文一致的信息：<br/>
![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@master/image/des-016.png)<br/>

如图，当以字符串 ``0123456\n`` 为明文输入时，该明文长度 $64$ 位，得到的密文为 $128$ 位（符合字节填充的要求），再次解密后得到与原始明文一致的信息：<br/>
![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@master/image/des-017.png)<br/>

如图，当以字符串 ``abcd\n`` 为明文输入时，该明文长度 $40$ 位，得到的密文为 $64$ 位（符合字节填充的要求），再次解密后得到与原始明文一致的信息：<br/>
![](https://cdn.jsdelivr.net/gh/sherryjw/StaticResource@v1.5.2/image/des-018.png)<br/>

<br/><br/>
