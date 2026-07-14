# 公共格式

公共格式均以独立整数主版本标识。实现必须拒绝未知主版本，不得猜测解析。

| 格式 | 当前版本 | 标识 |
| --- | ---: | --- |
| 包清单 | 1 | `[包].格式`，缺省 1 仅为 0.7 迁移兼容 |
| 锁文件 | 1 | `lock_version` |
| 字节码块 | 1 | `Chunk.format_version` |
| 测试报告 | 1 | `schema_version`和`test-report-v1` URI |
| 兼容报告 | 1 | `schema_version`和`compatibility-report-v1` URI |
| C ABI 结果 | 1 | JSON `schema`字段 |
| 标准库清单 | 1 | `schema_version`和`stdlib-api-v1` URI |

格式 1 中可以增加接收方明确忽略的可选字段；删除字段、改变字段类型或语义、改变默认值都需要新主版本。锁文件和字节码要求精确主版本匹配；报告消费者应按 schema URI 选择解析器。
