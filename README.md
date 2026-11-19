# 链下数据持有与完整性验证

本项目实现分布式加密存储中的数据持有与完整性验证。文件经过认证加密和纠删编码后分散存储，验证方通过抽样挑战检查数据是否仍被正确保存，并可利用足够数量的有效分片恢复文件。实现包含聚合证明与逐块签名两种验证方式，可用于比较通信开销和损坏检测效果。

**贡献者：** 王者、翁晨天、何柯阳、潘启颖、韩蒙

**资助信息：** 本项目受国家重点研发计划项目“基于区块链的新型信任体系”资助（项目编号：2023YFB2704400）。

[技术报告](docs/technical-report.pdf) · [实验数据](data/published-results/) · [运行验证](docs/VALIDATION.md)

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

算法说明、实验设计及参考文献见[技术报告](docs/technical-report.pdf)。引用报告时请保留原作者署名；复现实验时请注明所使用的代码版本和配置。代码与数据的版本关系见[来源说明](docs/SOURCES.md)。

## 许可

仓库自有代码及配套使用说明采用[MIT许可](LICENSE)。技术报告、研究论文和第三方数据保留各自署名及权利；MIT许可不替代其原有授权。
