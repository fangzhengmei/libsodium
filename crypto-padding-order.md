# 填充去除、AEAD 认证与 secretstream 流结束确认的传播顺序分析

分析对象：本仓库（libsodium，分支 `task/90`，HEAD `c000d33`）源码。
验证方式：从本仓库源码静态编译 `libsodium.a`，在仓库外独立目录
（`/srv/fb2/fangzhengmei/tasks/90/padding-order-demo/`）编写两个 C 程序实际调用 API。
本文明确区分 **【源码已证实】** 与 **【假设/未验证】** 两类结论。

---

## 1. 结论速览（责任划分）

| 职责 | 负责方 | 证据 |
|---|---|---|
| 长度隐藏（把明文补齐到块长，使密文长度不泄露真实明文长度） | **应用层**：加密前自行调 `sodium_pad` | AEAD/secretstream 源码中没有任何对 `sodium_pad`/`sodium_unpad` 的调用（全树 grep 可证），它们只透传长度 |
| 密文/标签/AD 的真实性认证（Poly1305 MAC 校验） | **库**：AEAD 与 secretstream 的 decrypt/pull 内部完成 | `aead_chacha20poly1305.c:230`、`aead_xchacha20poly1305.c:130`、`secretstream_xchacha20poly1305.c:239` |
| 认证通过后才解密、才输出明文与 tag | **库**：verify-then-decrypt，且有 `ACQUIRE_FENCE` | `aead_chacha20poly1305.c:235-240`、`secretstream_xchacha20poly1305.c:239-245` |
| 认证失败后的去填充 | **不发生**：失败路径直接返回 `-1`，应用不应再对该缓冲调 `sodium_unpad` | 失败时输出缓冲被清零、长度输出置 0 |
| 认证成功后的去填充（`sodium_unpad`） | **应用层** | 填充方案（blocksize、0x80 规则）只有应用知道 |
| 流结束（EOF）确认 | **应用层**：`TAG_FINAL` 只是一个被认证的标签值，库不维护"已关闭"状态 | `crypto_secretstream_xchacha20poly1305.h:50-52`；实测 FINAL 之后 push/pull 仍成功 |

一句话：**库负责"先认证、后解密、再交付"；应用负责"加密前填充、认证成功后去填充、看到 FINAL 后自行停止收流"。**

---

## 2. 三个接口各自的语义（源码已证实）

### 2.1 `sodium_pad` / `sodium_unpad`（`src/libsodium/sodium/utils.c:755-827`）

填充格式为 ISO 7816-4 风格：填充区为一个 `0x80` 后跟若干 `0x00`，填充长度在
`1..blocksize` 之间（即明文恰好对齐时也补一整块）。

- `sodium_pad`（utils.c:755）：计算 `xpadlen`，写入 `0x80`/`0x00`，返回填充后长度。
  `blocksize<=0` 或 `max_buflen` 不足时返回 `-1`。
- `sodium_unpad`（utils.c:798）：
  - 只检查缓冲**末尾的 `blocksize` 个字节**；`padded_buflen < blocksize` 或
    `blocksize<=0` 立即返回 `-1`（utils.c:809）。
  - 从尾字节向前扫描，用纯算术（无数据依赖分支）判断是否恰好存在一个 `0x80`
    且其前的填充字节全为 `0x00`（utils.c:817-823）。
  - 返回值 `(int) valid - 1`：合法为 `0`，坏填充为 `-1`（utils.c:826）。
  - 注意：**即使返回 `-1`，`*unpadded_buflen_p` 仍会被写入一个值**
    （utils.c:824），调用方在返回非 0 时必须忽略它。
  - 该函数**没有任何密钥或认证上下文**——它不知道也不关心数据是否通过认证。

### 2.2 AEAD（chacha20poly1305 / xchacha20poly1305）

以 IETF 变体 `crypto_aead_chacha20poly1305_ietf_decrypt_detached`
（`aead_chacha20poly1305.c:276-328`；xchacha 版本 `aead_xchacha20poly1305.c:90-143`
结构相同）为例，pull 侧顺序为：

1. 由密钥+nonce 派生 Poly1305 一次性密钥，初始化 MAC（行 294-296）。
2. 喂入 AD、密文 `c`、长度块（行 298-309）——**全程只处理密文，没有解密动作**。
3. `crypto_onetimeauth_poly1305_final` 得到计算出的 MAC（行 311）。
4. `crypto_verify_16`（常时比较，`crypto_verify/verify.c`）比对计算 MAC 与随附 MAC
   （行 315）。
5. 不一致：`memset(m, 0, mlen)` 清零输出区并 `return -1`（行 320-323）。
6. 一致：`ACQUIRE_FENCE`（获取屏障，`private/common.h:293`，防止编译器/CPU 把
   解密重排到比较之前）之后才 `crypto_stream_chacha20_ietf_xor_ic` 解密（行 324-325）。

封装层 `..._decrypt`（行 331-358）在 `clen < ABYTES` 时根本不调用 detached 解密，
`ret` 保持 `-1`，且只有 `ret==0` 时才设置 `*mlen_p`，否则其保持 `0`。

### 2.3 secretstream xchacha20poly1305（`secretstream_xchacha20poly1305.c`）

记录布局：`[1 字节加密 tag][密文][16 字节 Poly1305 MAC]`，
`ABYTES = 1 + 16`（头文件 `crypto_secretstream_xchacha20poly1305.h:17-18`）。

`..._pull`（行 180-262）的关键顺序：

1. 入口即把 `*mlen_p = 0`、`*tag_p = 0xff`（哨兵值）（行 195-200）；
   `inlen < ABYTES` 直接 `-1`（行 201）。
2. 计算 MAC，覆盖：AD（含对齐填充）、**加密后的 tag 块**（`block[0]=in[0]` 经
   chacha20 异或，行 216-222）、密文、两个 64 位长度块（行 224-233）。
3. `sodium_memcmp`（常时比较，utils.c:187）比对 MAC，失败则清掉临时 MAC 后
   `return -1`（行 239-242）。**此刻明文输出缓冲 `m` 一个字节都没被写过**，
   state（inonce/counter/key）也未推进。
4. MAC 通过后才经 `ACQUIRE_FENCE` 解密消息体（行 244-245），随后用 MAC 的前 8 字节
   异或推进 inonce、递增计数器、按 tag 决定是否 rekey（行 246-254），最后才回写
   `*mlen_p` 与 `*tag_p`（行 255-260）。

标签位定义（头文件行 38-52）：`MESSAGE=0x00`、`PUSH=0x01`、`REKEY=0x02`、
`FINAL = PUSH|REKEY = 0x03`。tag 在 push 侧被放进加密块并纳入 MAC，因此**篡改 tag
字节与篡改密文一样表现为 MAC 失败**，不存在"tag 可被单独伪造"的路径。

---

## 3. 坏填充 / 认证失败 / FINAL 的传播顺序

### 3.1 推荐组合下的完整调用链（应用负责拼接）

```
发送方:
  sodium_pad(明文, blocksize)                 ← 应用：长度隐藏
  AEAD_encrypt / secretstream_push(填充后明文) ← 库：加密+认证，对填充无感知
接收方:
  AEAD_decrypt / secretstream_pull(密文)       ← 库：先验 MAC，过了才解密
     失败 → return -1，输出清零/长度 0/tag 0xff，停止，绝不调 unpad
     成功 → 得到"已认证的填充明文"
  sodium_unpad(已认证明文, blocksize)          ← 应用：认证后去填充
     坏填充 → return -1（处理的是已认证数据，不是攻击者可控的解封结果）
  （secretstream）检查 tag == TAG_FINAL        ← 应用：自行确认 EOF 并停止
```

### 3.2 两类错误的传播次序与可区分性

**【源码已证实 + 实测确认】**

1. **认证失败先于一切**。坏 MAC、错 AD、过短记录在 AEAD/secretstream 内部即被拦截，
   返回 `-1`，执行流不会到达 `sodium_unpad`。因此"坏填充"与"认证失败"在正确实现中
   不可能针对同一条记录同时发生：
   - 认证失败 → 库返回 `-1`，应用看不到任何明文；
   - 认证成功但填充坏 → 库返回 `0`，随后应用自己的 `sodium_unpad` 返回 `-1`。
   两者在**调用序列层面可区分**（是哪一个函数返回的 `-1`），但**各自的 API 返回值
   层面不可区分**：所有失败都只有 `-1`，没有错误码分类。

2. 实测（demo2 D1/D2）同接口内不同失败原因的返回契约完全相同：
   - AEAD：篡改密文 vs 密文短于 ABYTES，都是 `ret=-1, *mlen_p=0`；
   - secretstream：篡改记录 vs 错误 AD vs 过短记录，都是
     `ret=-1, *mlen_p=0, *tag_p=0xff`。
   调用方无法（也不应试图）通过返回值区分攻击者是改了密文、改了 MAC 还是截断了记录。

3. **未认证内容不会交给上层**。实测（demo1 S3/S5）：
   - AEAD 认证失败时输出区被库 `memset` 为全 0（预置的 `0x5a` 毒字节被覆盖）；
   - secretstream 认证失败时输出区保持调用方原值（库在 MAC 通过前根本不触碰它，
     实测毒字节 `5a 5a 5a 5a` 原样保留），`mlen=0`、`tag=0xff`。
   两种写法都保证：失败时没有任何"解密结果"被产出，应用只要遵守"非 0 即丢弃"的
   契约就不会消费未认证字节。

4. 失败不推进流状态。实测（demo2 D4）：secretstream 一次失败的 `pull` 后，用原记录
   重试成功——inonce/counter 的更新位于 MAC 检查之后（源码行 246-249），失败路径
   不执行它们。

### 3.3 FINAL 的语义：被认证的建议，不是强制 EOF

**【源码已证实 + 实测确认】**

- `TAG_FINAL(0x03)` 与普通 tag 走完全相同的加密+MAC 路径，pull 成功后原样回传给
  应用；库内部没有任何"收到 FINAL 后进入关闭态"的分支（pull 函数全文无 FINAL 特判）。
- 实测（demo2 D3/D5）：push 出一条 FINAL 记录后**继续 push 仍返回 0**；pull 侧收到
  FINAL 后**继续 pull 下一条新记录也返回 0**。
- 实测（demo1 S6，且与官方测试 `test/default/secretstream_xchacha20poly1305.c:118-121`
  一致）：FINAL 记录 pull 成功后，**再次 pull 同一条旧记录返回 `-1`**——原因不是
  "流已关闭"，而是 state 已推进，旧 MAC 在新 inonce/counter 下校验不过。
- 因此"流是否真的结束"必须由应用根据 tag 自行判断并停止读取；库只保证 tag 本身
  真实未被篡改。

### 3.4 长度隐藏为什么是应用的责任

**【源码已证实】** AEAD 与 secretstream 对消息是长度透传的：
`clen = mlen + ABYTES`（`aead_chacha20poly1305.c:187`、secretstream 行 174），
库不做任何块对齐。全树 grep 确认 `sodium_pad/sodium_unpad` 的调用方只有测试
（`test/default/sodium_utils.c`、`misuse.c`），没有任何生产密码学模块调用它们。
是否填充、用多大 blocksize、何时去除，完全由应用在加密前/解密后编排。

---

## 4. 本地可重复的调用序列与实测结果

### 4.1 复现步骤

```sh
# 1) 从本仓库源码构建静态库（与系统 libsodium 无关）
cd /srv/fb2/fangzhengmei/0090-libsodium-6-c7d4f567
./autogen.sh -s -b
./configure --disable-dependency-tracking --disable-shared --enable-static --disable-pie
make -j12 -C src/libsodium

# 2) 构建并运行两个演示程序（位于仓库外独立目录）
cd /srv/fb2/fangzhengmei/tasks/90/padding-order-demo
./build.sh
./padding_order_demo     # S1-S7
./padding_order_demo2    # D1-D5
```

### 4.2 场景与实测结果摘要

| 编号 | 调用序列 | 实测返回/现象 | 说明 |
|---|---|---|---|
| S1 | 对全 0 缓冲调 `sodium_unpad`（无 0x80） | `-1`；对照合法填充返回 `0` 且长度正确 | 坏填充由 unpad 独立检出；失败时长度出参仍被写，须忽略 |
| S2 | `sodium_pad` → xchacha AEAD encrypt → decrypt → `sodium_unpad` | 全 `0`，还原原文 | 正常基线：填充对 AEAD 透明 |
| S3 | S2 密文翻转 1 字节后 decrypt | `-1`，`mlen=0`，输出区被清零 | 认证失败，未认证字节不交付 |
| S4 | 把"填充损坏"的明文**合法加密**后 decrypt 再 unpad | decrypt `0` → unpad `-1` | 库不管填充；坏填充在认证之后才由应用发现 |
| S5 | secretstream 两条记录（第二条带 FINAL），翻转 FINAL 记录 1 字节后 pull | `-1`，`mlen=0`，`tag=0xff`，输出缓冲未被写 | MAC 先于解密；tag 也无法交付 |
| S6 | 原样 pull FINAL 记录，再重复 pull 同一记录 | 首次 `0, tag=0x03`；再次 `-1` | FINAL 正常交付；重放失败源于 state 推进而非 EOF 强制 |
| S7 | secretstream 封装"坏填充明文"，pull 后 unpad | pull `0, tag=0x00` → unpad `-1` | 与 S4 同理，去填充属应用层 |
| D1 | AEAD：篡改密文 vs 过短密文 | 均为 `-1, mlen=0` | 同接口错误不可区分 |
| D2 | secretstream：篡改 vs 错 AD vs 过短 | 均为 `-1, mlen=0, tag=0xff` | 同接口错误不可区分 |
| D3 | FINAL 之后继续 `push` | `push` 仍返回 `0` | 库不强制 EOF |
| D4 | 失败 pull 后用原记录重试 | 重试 `0` 且明文正确 | 失败不推进 state |
| D5 | pull 到 FINAL 后继续 pull 下一条 | 下一条仍 `0, tag=0x00` | 无"关闭态"，EOF 由应用确认 |

---

## 5. 正确用法要点与陷阱

**【源码已证实的约束 + 推导的用法规则】**

1. 必须"先认证、后去填充"。`sodium_unpad` 本身无认证能力；若应用在 AEAD/secretstream
   返回 `-1` 时仍对缓冲去填充并使用结果，属于应用缺陷——库无法阻止。
2. 检查**每一个**返回值：AEAD/secretstream 非 0 即丢弃整条记录并停止当前处理；
   `sodium_unpad` 非 0 时忽略其长度出参（utils.c:824 仍会写它）。
3. 不要依赖返回值区分失败原因；统一按"认证/格式失败"处理，避免给攻击者返回可观测的
   差异化响应。
4. secretstream 的 EOF 判定 = 应用收到 `tag == TAG_FINAL` 后自行停止；不要假设库会
   拒绝 FINAL 之后的数据。
5. 长度隐藏的强度取决于应用选择的 blocksize：填充只能把长度隐藏到块长粒度，
   记录数量、时序等流量特征不在库的保护范围内。

---

## 6. 尚未验证的假设（明确标注）

1. **【假设】时序侧信道层面的错误可区分性**：`sodium_unpad` 的内存扫描本身是无数据
   依赖分支的常时写法（utils.c:817-823），`crypto_verify_16`/`sodium_memcmp` 也是常时
   比较；但应用在 unpad 成功/失败后的处理分支、以及 AEAD 失败时 `memset` 耗时与
   成功路径解密耗时的差异，是否构成可远程观测的时序信号，本文未做测量，属未验证项。
2. **【假设】其他 AEAD 实现的同构性**：本文逐行核实了 chacha20poly1305 与
   xchacha20poly1305 的 verify-then-decrypt 顺序；AEGIS、AES-GCM 系列仅依据相同的
   API 契约与失败清零模式推断行为一致，未在本次演示中逐一实测。
3. **【假设】编译器/链接时优化对 `ACQUIRE_FENCE` 语义的保持**：屏障在主流
   C11/GCC 原子语义下有效（common.h:293-297），但极端 LTO/专用工具链下是否可能被
   弱化未做验证；实测所用的普通 `-O0` 构建顺序正确。
4. **【假设】并发场景**：同一 state 被多线程并发 `pull` 的行为库未定义（state 非线程
   安全），本文只覆盖单线程调用序列。
5. **【未验证】`sodium_unpad` 对 `padded_buflen` 远大于实际缓冲时的内存安全性**：
   函数按调用方给定长度向回扫描 `blocksize` 字节，越界保护依赖调用方传入真实长度，
   本文未构造越界测试（且该责任在调用方）。

---

## 附：关键源码索引

| 事实 | 位置 |
|---|---|
| `sodium_pad` / `sodium_unpad` 实现 | `src/libsodium/sodium/utils.c:755-827` |
| AEAD 验 MAC→清零/屏障→解密 | `src/libsodium/crypto_aead/chacha20poly1305/aead_chacha20poly1305.c:276-358` |
| xchacha AEAD 同构实现 | `src/libsodium/crypto_aead/xchacha20poly1305/aead_xchacha20poly1305.c:90-143` |
| secretstream pull 全流程 | `src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c:180-262` |
| tag 常量（FINAL=0x03） | `src/libsodium/include/sodium/crypto_secretstream_xchacha20poly1305.h:38-52` |
| `ACQUIRE_FENCE` 定义 | `src/libsodium/include/sodium/private/common.h:293-297` |
| 官方 secretstream 测试（含 FINAL 后重拉失败） | `test/default/secretstream_xchacha20poly1305.c:103-146` |
| 官方填充往返测试 | `test/default/sodium_utils.c:191-219` |
| 本地复现程序 | `/srv/fb2/fangzhengmei/tasks/90/padding-order-demo/`（仓库外） |
