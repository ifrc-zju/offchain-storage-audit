# 链下数据持有与完整性验证

面向分布式加密存储的实验实现，对应指标1.2。采用认证加密、纠删编码和公开可验证的数据持有证明，比较聚合证明与逐块签名返回的通信开销，并验证数据损坏检测及文件恢复。

[技术报告](docs/technical-report.pdf) · [历史统计数据](data/published-results/) · [发布验证](docs/VALIDATION.md)

## 方法与代码

- `tools/protocol.py`：AES-GCM、Reed–Solomon编码、公开同态认证与Ed25519对照方法。
- `tools/test_protocol.py`：正常证明、篡改、重放、编码错误、参数绑定和恢复验证。
- `tools/run_experiment.py`：实验配置、数据生成和测量；`analyze_results.py`负责汇总。

## 快速开始

需要Python 3.12。先安装依赖：

```bash
python -m venv .venv
# Windows: .venv/Scripts/activate
# Linux/macOS: source .venv/bin/activate
python -m pip install -r requirements.txt
```

```bash
python tools/test_protocol.py
python tools/demo.py --output demo-output
```

示例生成1,025字节合成对象，分布到6个逻辑节点，验证正常证明、篡改拒绝及4节点恢复。输出仅包含公开参数、挑战、证明和结果；测试私钥位于临时目录，退出后清理。输出目录须不存在。

完整实验使用`tools/config.json`，运行`python tools/run_experiment.py`。该命令会创建较多测试输入与结果，请预留运行时间和磁盘空间。逻辑节点在同一进程内顺序执行，没有测量真实跨主机网络延迟。

## 数据与结果

`data/published-results`保留历史主实验的按种子及汇总统计；它们来自2026年9月的既有实验，并非本次发布时重新测出的性能数值。公开示例见`data/example`，也可由上述命令重新生成。

当前源码保留了采样种子派生修正；历史主实验统计仍对应修正前的原记录。发布验证覆盖当前源码的功能正确性，未重跑完整性能实验。具体来源见[来源说明](docs/SOURCES.md)。

## 署名与引用

技术报告作者以PDF为准。仓库整理和运行适配不改变报告署名，报告作者不自动等同于每段代码的开发者。后续贡献通过提交和审阅记录注明。

## 许可

仓库自有代码及配套使用说明采用[MIT许可](LICENSE)。技术报告、研究论文和第三方数据保留各自署名及权利；MIT许可不替代其原有授权。
