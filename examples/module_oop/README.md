# 跨模块对象示例

本示例由四个模块组成：`base.yx`声明公开类与协议，`controls.yx`跨模块继承并
实现协议，`facade.yx`公开重导出两个模块，`main.yx`只通过 facade 使用完整 API。

从仓库根目录运行：

```sh
yanxu check examples/module_oop/main.yx
yanxu examples/module_oop/main.yx
yanxu 字节 examples/module_oop/main.yx
```

树解释器与字节码 VM 都应输出：

```text
视图：确定（按钮）
真
真
真
视图
```
