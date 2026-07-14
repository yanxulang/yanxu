# C 宿主示例

先在核心仓库运行`cargo build --release`生成动态库。macOS/Linux 示例命令：

```sh
cc main.c -I../../../include -L../../../target/release -lyanxu -o yanxu-c-host
DYLD_LIBRARY_PATH=../../../target/release ./yanxu-c-host # macOS
LD_LIBRARY_PATH=../../../target/release ./yanxu-c-host    # Linux
```

返回值是`YANXU_ABI_SCHEMA == 1`的 JSON。引擎与字符串都必须用头文件声明的对应释放函数释放；默认引擎不授予宿主能力。
