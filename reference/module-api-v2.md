# 模块 API 清单 v2

`yanxu 文 --json <文卷>` 从模块 API 清单格式 1 升级到格式 2。新清单使用
`https://yanxu.dev/schemas/module-api-v2.json`，消费者必须先检查
`format_version`，不得把格式 1 的字符串字段按格式 2 解释。

## 字段迁移

| 格式 1 | 格式 2 |
| --- | --- |
| `format_version: 1` | `format_version: 2` 与 `$schema` |
| 顶层 `module` 字符串 | 保留 `module`，新增结构化 `module_id` |
| 声明 `name` | 保留 `name`，新增 `owner_module`、`original_module`、`qualified_name` 与 `exposed_path` |
| 类型字符串 | `RuntimeType` 递归对象；人类可读拼写位于 `display_type` 或 `display_result` |
| `superclass` 字符串 | `TypeLink { source, target }` 或 `null` |
| `protocols` 字符串数组 | `TypeLink` 数组 |
| 无重导出记录 | `module_reexport` 声明及递归 `exports` |

`TypeLink.source.segments` 保存源码访问路径，例如 `["基础", "视图"]`；
`TypeLink.target` 保存解析后的规范 `TypeId`。导入别名只出现在 `source` 和
`exposed_path` 中，不参与 `target` 的类型身份。

重导出的类型继续使用原声明的 `type_id`、`owner_module` 与
`original_module`，同时通过 `exposed_path` 记录 facade 中的访问路径。不同模块中的
同名类或协议因此可以被机器消费者可靠区分。

## 标准库清单

`yanxu 标准库 --json` 使用的 `stdlib-api-v1.json` 是独立、已版本化的标准库
ABI 清单。本次升级不改变其 schema，也不要求标准库清单消费者迁移。
