# secure-container: MK-TME 容器机密性原型

这个仓库提供一个面向论文原型的实现：
- 将容器抽象为独立“机密域”；
- 使用 MK-TME keyid（真实或 mock）为每个容器分配隔离密钥域；
- 模拟跨容器攻击并输出可用于论文图表的数据。

> 你的环境（Linux 5.15 + MK-TME syscall patch + Intel 4514Y）可以直接切换到真实 syscall 模式。

## 目录结构

- `prototype/mktme_syscalls.py`：syscall 封装层（real/mock 双模式）。
- `prototype/mktme_isolation_demo.py`：核心 demo，执行容器间攻击验证。
- `scripts/run_experiments.py`：批量实验脚本，输出 `summary.csv`。
- `docs/research-plan.md`：论文角度的研究问题与扩展方向。

## 快速运行（mock 模式）

```bash
python3 prototype/mktme_isolation_demo.py --containers 8 --output artifacts/demo
```

预期：
- `successful_attacks = 0`
- 在 `artifacts/demo/report.json` 看到每个容器的 keyid 与攻击结果。

## 切换到真实 MK-TME syscall 模式

请根据你补丁中的 syscall 编号设置：

```bash
export MKTME_SYSCALL_ALLOC_KEY=<nr1>
export MKTME_SYSCALL_PROTECT_RANGE=<nr2>
export MKTME_SYSCALL_FREE_KEY=<nr3>
python3 prototype/mktme_isolation_demo.py --containers 8 --output artifacts/real
```

只要三个环境变量都存在，系统会自动进入 `mode=real`。

## 批量实验（用于论文图）

```bash
python3 scripts/run_experiments.py
cat artifacts/batch/summary.csv
```

可以直接绘制 “容器规模 vs 跨容器攻击成功次数” 曲线。

## 调试建议

- 首先在 mock 模式验证逻辑与实验脚本。
- 在真实模式下，若 syscall 报错，优先核对 syscall 编号与参数签名。
- 用 `python3 -m pdb prototype/mktme_isolation_demo.py ...` 逐步检查 key 生命周期。

## 与 TDX 的结合建议

当前仓库已形成可测量的容器密钥域控制面。下一步可把控制面进程放入 TDX TD 内，
将 key 分配策略、容器身份声明、审计日志签名都纳入可信执行边界，实现：
1. 宿主机不可见的策略状态；
2. 可远程证明的容器机密性编排；
3. “TDX + MK-TME” 分层防护论文故事线。
