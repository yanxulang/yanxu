# 字节码格式 2

字节码格式 2 为跨模块对象模型提供可序列化、可校验的规范身份。外层 YXB
格式仍为 1，但`bytecode_format`和每个`Chunk.format_version`必须为 2。

## 身份与链接

每个`Chunk`保存声明模块的`ModuleId`。包应用编译使用稳定的`app:`或`pkg:`
逻辑 ID，不把本机绝对路径写入可移植制品。`ClassPrototype`与
`ProtocolPrototype`保存`TypeId { module, name, kind }`；方法所有者也保存同一
`TypeId`。

参数、归值、域、局部绑定和`Instruction::IsType`使用递归`RuntimeType`：

- `Named`保存`TypeLink`；
- `Union`、`Nullable`、`Generic`和`Function`递归包含其他运行时类型；
- `TypeLink.source.segments`保存源码访问路径；
- `TypeLink.target`在编译时可确定时保存规范`TypeId`，否则由 VM 按模块导出链接。

父类链接只允许类目标，协议链接只允许协议目标。VM 链接后会核对实际对象的
`TypeId`，不会把导入别名或短名称当作身份。

## 校验与兼容

序列化、反序列化、YXB 校验和 VM 直接执行入口都会验证：

- 模块与类型身份合法；
- 嵌套函数块与外层模块身份一致；
- 类、协议和方法所有者种类正确；
- 所有递归类型路径与目标身份合法；
- YXB 模块索引与`Chunk.module_id`一致。

格式 1 的原型使用裸类型字符串，无法无歧义恢复模块所有权，因此当前运行时会
返回明确的“不支持格式版本 1”错误，不提供猜测迁移。旧字节码或 YXB 应从源码
重新构建。格式 2 的 fuzz 入口继续要求任意输入不 panic，成功解码的归档必须可以
重新编码和解码。
