# 言序项目当前状态

本文件是核心仓库当前版本、公开格式和兼容基线的唯一状态真源。语言语义仍以[`../../spec/language/v1/`](../../spec/language/v1/)和可执行兼容语料为规范；历史台账只保存已经完成阶段的验收证据。

## 当前版本

- 当前源码版本：`1.1.16`
- 正式语言规范：版本 `1`
- 最早受兼容语料持续验证的源码版本：`0.3`
- Rust 最低支持版本：尚未声明；发布前不得据此推断任意旧工具链受支持

## 公开契约

| 契约 | 当前版本 | 兼容读取或提供 |
| --- | ---: | --- |
| 包清单 | 2 | 1、2 |
| 锁文件 | 2 | 1、2 |
| YXB | 1 | 1 |
| 字节码 | 2 | 2 |
| 原生扩展 ABI | 2 | 1、2 |
| 工程协议 | 1 | 1 |
| 标准库 API 清单 | 1 | 25 个模块 |
| 兼容报告 | 1 | 13 卷语料 |

以下 JSON 与上表共同维护，并由工作区测试直接核对实现常量、Cargo 版本、标准库清单和`compat/`内容。版本或计数变化而未同步本文件时，质量门禁会失败。

```json
{
  "status_schema": 1,
  "current_version": "1.1.16",
  "language_spec_version": 1,
  "manifest_format": { "current": 2, "readable": [1, 2] },
  "lock_format": { "current": 2, "readable": [1, 2] },
  "yxb_format": { "current": 1, "readable": [1] },
  "bytecode_format": { "current": 2, "readable": [2] },
  "native_abi": { "current": 2, "provided": [1, 2] },
  "engineering_protocol": { "current": 1, "readable": [1] },
  "stdlib_api_schema": 1,
  "stdlib_modules": 25,
  "compatibility_report_schema": 1,
  "compatibility_cases": 13,
  "minimum_supported_source_version": "0.3",
  "rust_msrv": null
}
```

## 历史台账

- [`archive/DEVELOPMENT_0_3_TO_0_7.md`](archive/DEVELOPMENT_0_3_TO_0_7.md)：0.3–0.7 完整性与验收记录。
- [`archive/ROADMAP_0_8_TO_1_0.md`](archive/ROADMAP_0_8_TO_1_0.md)：0.8–1.0 稳定化与发行后首轮扩建记录。

后续版本的实现计划不在本文件宣称为已完成；只有已经落入源码、测试与正式版本元数据的状态才可更新到这里。
