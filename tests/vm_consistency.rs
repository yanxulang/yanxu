use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use yanxu::bytecode;
use yanxu::interpreter::Interpreter;
use yanxu::vm::Vm;

fn execute_both(source: &str, directory: &Path) -> (Vec<String>, Vec<String>) {
    let statements = yanxu::parse_named(source, "<一致性规格>").unwrap();

    let mut interpreter = Interpreter::silent();
    interpreter
        .execute_in_directory(&statements, directory)
        .unwrap();

    let chunk = bytecode::compile(&statements).unwrap();
    let mut vm = Vm::silent();
    vm.execute_in_directory(&chunk, directory).unwrap();
    (interpreter.take_output(), vm.take_output())
}

fn assert_consistent(name: &str, source: &str) {
    let (tree, vm) = execute_both(source, Path::new("."));
    assert_eq!(tree, vm, "{name} 的树解释器与 VM 输出不一致");
}

#[test]
fn official_examples_type_check_and_match_both_runtimes() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples");
    let mut paths = fs::read_dir(&root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|extension| extension == "yx"))
        .collect::<Vec<_>>();
    paths.sort();

    for path in paths {
        let source = fs::read_to_string(&path).unwrap();
        let statements = yanxu::parse_named(&source, path.display().to_string()).unwrap();
        yanxu::type_checker::check_in_directory(&statements, &root)
            .unwrap_or_else(|errors| panic!("{} 静态检查失败：{errors:#?}", path.display()));
        let (tree, vm) = execute_both(&source, &root);
        assert_eq!(tree, vm, "{} 的树解释器与 VM 输出不一致", path.display());
    }
}

#[test]
fn standard_library_manifest_matches_types_and_both_runtimes() {
    let manifest = yanxu::stdlib::api_manifest().unwrap();
    for module in manifest["modules"].as_array().unwrap() {
        let name = module["name"].as_str().unwrap();
        let mut source = format!("引「标准:{name}」为 模块；\n");
        for member in module["members"].as_array().unwrap() {
            source.push_str(&format!("模块.{}；\n", member["name"].as_str().unwrap()));
        }
        let source_name = format!("<标准库清单:{name}>");
        let statements = yanxu::parse_named(&source, source_name.clone()).unwrap();
        yanxu::type_checker::check(&statements)
            .unwrap_or_else(|errors| panic!("{source_name} 静态摘要不完整：{errors:#?}"));
        let (tree, vm) = execute_both(&source, Path::new("."));
        assert_eq!(tree, vm, "{source_name} 的公开成员不一致");
    }
}

#[test]
fn binary_file_and_cli_arguments_match_both_runtimes() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("yanxu-binary-consistency-{unique}"));
    fs::create_dir_all(&root).unwrap();

    let run = |path: &Path, backend: &str| {
        let path = source_path(path);
        let source = format!(
            r#"
            引「标准:字节」为 字节；引「标准:文件」为 文件；引「标准:环境」为 环境；
            文件.写入字节（「{path}」，字节.从数列（【0，255】））；
            文件.追加字节（「{path}」，字节.从文字（「言序」））；
            定 数据：字节串 为 文件.读取字节（「{path}」）；
            言 字节.长度（数据）；言 字节.转数列（字节.切片（数据，0，2））；
            言 文件.状态（「{path}」）【「字节数」】；言 环境.参数（）；
            "#
        );
        let statements = yanxu::parse_named(&source, format!("<{backend}-二进制>")).unwrap();
        yanxu::type_checker::check(&statements).unwrap();
        if backend == "tree" {
            let mut interpreter = Interpreter::silent();
            interpreter.set_arguments(vec!["甲".into(), "--值".into()]);
            interpreter
                .execute_in_directory(&statements, &root)
                .unwrap();
            interpreter.take_output()
        } else {
            let chunk = bytecode::compile(&statements).unwrap();
            let mut vm = Vm::silent();
            vm.set_arguments(vec!["甲".into(), "--值".into()]);
            vm.execute_in_directory(&chunk, &root).unwrap();
            vm.take_output()
        }
    };

    let tree_path = root.join("tree.bin");
    let vm_path = root.join("vm.bin");
    let tree = run(&tree_path, "tree");
    let vm = run(&vm_path, "vm");
    assert_eq!(tree, vm);
    assert_eq!(fs::read(tree_path).unwrap(), fs::read(vm_path).unwrap());
    fs::remove_dir_all(root).unwrap();
}

fn source_path(path: &Path) -> String {
    path.display()
        .to_string()
        .replace('\\', "\\\\")
        .replace('」', "\\」")
}

#[test]
fn shared_language_semantics_match_the_tree_interpreter() {
    let cases = [
        (
            "值、分支与循环",
            r#"
                令 和：数 为 0；令 次：数 为 1；
                当 次 不大于 5 则
                    置 和 为 和 加 次；置 次 为 次 加 1；
                终
                若 和 等于 15 且 非 假 则 言「善」；否则 言「误」；终
            "#,
        ),
        (
            "递归、闭包与归值",
            r#"
                法 阶乘（值：数）：数 则
                    若 值 不大于 1 则 归 1；终
                    归 值 乘 阶乘（值 减 1）；
                终
                法 相加器（甲：数）：法（数）：数 则
                    法 加乙（乙：数）：数 则 归 甲 加 乙；终
                    归 加乙；
                终
                定 加七：法（数）：数 为 相加器（7）；
                言 阶乘（6）；言 加七（8）；
            "#,
        ),
        (
            "容器、结构相等、切片与改写",
            r#"
                令 列表：列<数> 为【3，1，2】；
                置 列表【0】为 4；追加（列表，5）；
                令 对照：典<文,数> 为{「甲」：1}；置 对照【「乙」】为 2；
                言 列表【1：4】；言 对照【「乙」】；
                言（1，「二」）等于（1，「二」）；
                言 排序（列表）；
            "#,
        ),
        (
            "统一惰性迭代协议",
            r#"
                法 倍（值：数）：数 则 归 值 乘 2；终
                法 偶（值：数）：理 则 归 值 除 2 等于 值 除 2；终
                法 求和（合：数，值：数）：数 则 归 合 加 值；终
                定 流 为 映射（范围（1，5），倍）；
                言 续（遍（流））；
                言 折叠（范围（1，5），0，求和）；
                言 反转（「天地玄」）；言 包含（【1，2，3】，2）；
            "#,
        ),
        (
            "协议、继承、字段与方法绑定",
            r#"
                协 可名 则 域 名：文；法 显示（）：文；终
                类 生灵 则 法 显示（）：文 则 归 此.名；终 终
                类 人 承 生灵 纳 可名 则
                    公 只 域 名：文；静 域 数目：数 为 0；
                    法 初始化（名：文）则 置 此.名 为 名；终
                    静 法 类名（）：文 则 归「人」；终
                终
                定 子：可名 为 人（「子路」）；
                定 展示：法（）：文 为 子.显示；
                言 展示（）；言 人.类名（）；言 人.数目；
            "#,
        ),
        (
            "父类调用、继承类型与原生类型判断",
            r#"
                协 可名 则 法 自述（）：文；终
                类 生灵 则
                    公 域 名：文；
                    法 初始化（名：文）则 置 此.名 为 名；终
                    法 自述（）：文 则 归「生灵：」加 此.名；终
                终
                类 人 承 生灵 纳 可名 则
                    法 初始化（名：文）则 父.初始化（名）；终
                    法 自述（）：文 则 归 父.自述（）加「：人」；终
                终
                定 子：人 为 人（「子路」）；
                定 长者：生灵 为 子；
                言 子.自述（）；言 长者 是 生灵；言 子 是 可名；
                言 子 是 文；言【1，2】是 列<数>；
            "#,
        ),
        (
            "结构化错误",
            r#"
                法 失败（）：数 则 归 1 除 0；终
                试 则 失败（）；救 错 则
                    言 错.消息；言 长度（错.踪迹）不小于 1；
                终
            "#,
        ),
        (
            "套接字类型与结构化错误",
            r#"
                引「标准:套接字」为 套接字；
                试 则 套接字.TCP连接（「没有端口」，100）；
                救 错 则 言 错.代码；言 错.类别；终
                试 则 套接字.TCP连接（「127.0.0.1:1」，0）；
                救 错 则 言 错.代码；终
                定 数据报：套接字 为 套接字.UDP绑定（「127.0.0.1:0」）；
                试 则 套接字.UDP接收自（数据报，0，100）；
                救 错 则 言 错.代码；终
                套接字.关闭（数据报）；
            "#,
        ),
        (
            "UDP 套接字有界收发",
            r#"
                引「标准:套接字」为 套接字；
                定 收方：套接字 为 套接字.UDP绑定（「127.0.0.1:0」）；
                定 发方：套接字 为 套接字.UDP绑定（「127.0.0.1:0」）；
                定 地址：文 为 套接字.本地地址（收方）；
                言 套接字.UDP发送至（发方，「善哉」，地址，1000）；
                定 数据：典<文,文> 为 套接字.UDP接收自（收方，16，1000）；
                言 数据【「正文」】；
                套接字.关闭（收方）；套接字.关闭（发方）；
            "#,
        ),
    ];

    for (name, source) in cases {
        assert_consistent(name, source);
    }
}

#[test]
fn relative_modules_have_matching_exports_and_single_initialization() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("yanxu-vm-consistency-{unique}"));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("算书.yx"),
        "言「模块已载」；公 定 基数：数 为 40；公 法 加二（值：数）：数 则 归 值 加 2；终",
    )
    .unwrap();
    let source = r#"
        引「算书.yx」为 甲；引「算书.yx」为 乙；
        言 甲.加二（甲.基数）；言 乙.基数；
    "#;

    let (tree, vm) = execute_both(source, &root);
    assert_eq!(tree, ["模块已载", "42", "40"]);
    assert_eq!(tree, vm);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn format_two_package_alias_exports_and_transitive_isolation_match_both_runtimes() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("yanxu-package-parity-{unique}"));
    let app = root.join("app");
    let tool = root.join("tool");
    let core = root.join("core");
    for directory in [&app, &tool, &core] {
        fs::create_dir_all(directory.join("src")).unwrap();
    }
    fs::write(
        core.join("言序.toml"),
        r#"[包]
格式 = 2
名称 = "内核库"
版本 = "1.0.0"
言序 = ">=1.1.5"
入口 = "src/主.yx"
[导出]
默认 = "src/主.yx"
"#,
    )
    .unwrap();
    fs::write(core.join("src/主.yx"), "公 定 基数：数 为 40；").unwrap();
    fs::write(
        tool.join("言序.toml"),
        r#"[包]
格式 = 2
名称 = "工具库"
版本 = "1.0.0"
言序 = ">=1.1.5"
入口 = "src/主.yx"
[依赖]
内核 = { 包 = "内核库", 路径 = "../core", 版 = "^1" }
[导出]
默认 = "src/主.yx"
公开 = "src/公开.yx"
"#,
    )
    .unwrap();
    fs::write(tool.join("src/主.yx"), "公 定 名：文 为「工具」；").unwrap();
    fs::write(
        tool.join("src/公开.yx"),
        "引「包:内核」为 内核；公 法 答案（）：数 则 归 内核.基数 加 2；终",
    )
    .unwrap();
    fs::write(
        app.join("言序.toml"),
        r#"[包]
格式 = 2
名称 = "应用"
版本 = "1.0.0"
言序 = ">=1.1.5"
入口 = "src/主.yx"
[依赖]
工具别名 = { 包 = "工具库", 路径 = "../tool", 版 = "^1" }
"#,
    )
    .unwrap();
    let manifest = yanxu::package::load(app.join("言序.toml")).unwrap();
    let graph = yanxu::package::ensure_lock_with_dev(&manifest, true).unwrap();
    assert_eq!(graph.packages.len(), 2);

    let source = "引「包:工具别名/公开」为 工具；言 工具.答案（）；";
    let statements =
        yanxu::parse_named(source, app.join("src/主.yx").display().to_string()).unwrap();
    yanxu::type_checker::check_in_directory(&statements, app.join("src")).unwrap();
    let (tree, vm) = execute_both(source, &app.join("src"));
    assert_eq!(tree, ["42"]);
    assert_eq!(tree, vm);

    let forbidden = yanxu::parse("引「包:内核」为 内核；").unwrap();
    let mut interpreter = Interpreter::silent();
    let tree_error = interpreter
        .execute_in_directory(&forbidden, &app.join("src"))
        .unwrap_err()
        .to_string();
    let chunk = bytecode::compile(&forbidden).unwrap();
    let mut vm = Vm::silent();
    let vm_error = vm
        .execute_in_directory(&chunk, &app.join("src"))
        .unwrap_err()
        .to_string();
    for error in [tree_error, vm_error] {
        assert!(error.contains("未声明依赖别名“内核”"), "{error}");
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn shared_runtime_failures_retain_the_same_error_category() {
    let source = "法 加一（值：数）：数 则 归 值 加 1；终 加一（「错」）；";
    let statements = yanxu::parse(source).unwrap();

    let mut interpreter = Interpreter::silent();
    let tree_error = interpreter.execute(&statements).unwrap_err().to_string();

    let chunk = bytecode::compile(&statements).unwrap();
    let mut vm = Vm::silent();
    let vm_error = vm.execute(&chunk).unwrap_err().to_string();

    for error in [&tree_error, &vm_error] {
        assert!(error.contains("变量“值”注为数，不可纳入文"), "{error}");
        assert!(error.contains("<文句>:1"), "{error}");
    }
}

#[test]
fn expanded_pure_standard_modules_match_both_runtimes() {
    let source = r#"
        引「标准:路径」为 路径；
        引「标准:环境」为 环境；
        引「标准:哈希」为 哈希；
        引「标准:编码」为 编码；
        引「标准:统计」为 统计；
        引「标准:CSV」为 CSV；
        引「标准:随机」为 随机；
        引「标准:标识」为 标识；
        引「标准:模板」为 模板；
        引「标准:校验」为 校验；
        言 路径.规范化（「甲/乙/../丙」）；
        言 路径.扩展名（「档案.yx」）；
        言 环境.系统（）；言 环境.架构（）；
        言 哈希.SHA256（「言序」）；
        言 编码.解十六进制（编码.十六进制（「言序」））；
        言 编码.解百分号（编码.百分号（「言序 /?」））；
        言 统计.总和（【1，2，3，4】）；
        言 统计.平均（【1，2，3，4】）；
        言 统计.方差（【1，2，3，4】）；
        定 表：列<列<文>> 为 CSV.解析（「甲,乙\n一,\"二,三\"」）；
        言 表【1】【1】；言 CSV.序列化（表）；
        言 随机.整数（42，10，20）；
        定 标号：文 为 标识.稳定UUID（「言序」）；
        言 标号；言 标识.是否UUID（标号）；
        言 模板.插值（「问{{name}}安」，「name」，「子衿」）；
        言 模板.反转义HTML（模板.转义HTML（「<言序>」））；
        言 校验.电子邮件（「hello@yanxu.dev」）；
        言 校验.IPv4（「127.0.0.1」）；
        言 校验.十六进制色（「#7fef6d」）；
    "#;
    let (tree, vm) = execute_both(source, Path::new("."));
    assert_eq!(tree, vm);
    assert_eq!(tree[4], yanxu::stdlib::sha256("言序"));
    assert_eq!(tree[7..10], ["10", "2.5", "1.25"]);
    assert_eq!(
        tree[12..],
        [
            "13",
            "7fef6d82-32f7-8809-a49c-11a4e2944571",
            "真",
            "问子衿安",
            "<言序>",
            "真",
            "真",
            "真"
        ]
    );
}

#[test]
fn one_one_standard_modules_match_both_runtimes() {
    let source = r#"
        引「标准:Base64」为 Base64；
        引「标准:正则」为 正则；
        引「标准:URL」为 URL；
        引「标准:日期」为 日期；
        定 编码值：文 为 Base64.编码（「言序」）；
        言 Base64.解码（编码值）；
        言 Base64.解网址编码（Base64.网址编码（「言序/语言」））；
        言 正则.匹配（「^言.+$」，「言序」）；
        言 正则.首项（「[0-9]+」，「甲12乙」）；
        言 正则.替换全部（「[0-9]+」，「甲12乙34」，「数」）；
        言 正则.分割（「[,，]」，「甲,乙，丙」）；
        定 地址：文 为「https://yanxu.dev:8443/docs/start?lang=zh」；
        言 URL.协议（地址）；言 URL.主机（地址）；言 URL.端口（地址）；
        言 URL.路径（地址）；言 URL.查询值（地址，「lang」）；
        言 URL.合并（「https://yanxu.dev/docs/」，「../download」）；
        言 日期.是否合法（「2024-02-29」）；
        言 日期.是否闰年（2000）；
        言 日期.加天（「2024-02-28」，2）；
        言 日期.相差天数（「2024-02-28」，「2024-03-01」）；
    "#;
    let (tree, vm) = execute_both(source, Path::new("."));
    assert_eq!(tree, vm);
    assert_eq!(
        tree,
        [
            "言序",
            "言序/语言",
            "真",
            "12",
            "甲数乙数",
            "【甲，乙，丙】",
            "https",
            "yanxu.dev",
            "8443",
            "/docs/start",
            "zh",
            "https://yanxu.dev/download",
            "真",
            "真",
            "2024-03-01",
            "2",
        ]
    );
}

#[test]
fn one_one_standard_module_errors_match_both_runtimes() {
    let cases = [
        (
            "Base64",
            "引「标准:Base64」为 Base64；言 Base64.解码（「***」）；",
            "Base64文字含非法",
        ),
        (
            "正则",
            "引「标准:正则」为 正则；言 正则.匹配（「[」，「言序」）；",
            "正则模式不合法",
        ),
        (
            "URL",
            "引「标准:URL」为 URL；言 URL.协议（「不是URL」）；",
            "URL 不合法",
        ),
        (
            "日期",
            "引「标准:日期」为 日期；言 日期.加天（「2023-02-29」，1）；",
            "有效公历范围",
        ),
    ];

    for (name, source, expected) in cases {
        let source_name = format!("<1.1-{name}-错误>");
        let statements = yanxu::parse_named(source, source_name.clone()).unwrap();
        let mut interpreter = Interpreter::silent();
        let tree_error = interpreter.execute(&statements).unwrap_err().to_string();
        let chunk = bytecode::compile(&statements).unwrap();
        let mut vm = Vm::silent();
        let vm_error = vm.execute(&chunk).unwrap_err().to_string();
        for runtime_error in [&tree_error, &vm_error] {
            assert!(runtime_error.contains(expected), "{runtime_error}");
            assert!(runtime_error.contains(&source_name), "{runtime_error}");
        }
    }
}

#[test]
fn post_one_zero_standard_module_errors_match_both_runtimes() {
    let source = "引「标准:随机」为 随机；言 随机.整数（1，2，2）；";
    let statements = yanxu::parse_named(source, "<标准库错误规格>").unwrap();

    let mut interpreter = Interpreter::silent();
    let tree_error = interpreter.execute(&statements).unwrap_err().to_string();

    let chunk = bytecode::compile(&statements).unwrap();
    let mut vm = Vm::silent();
    let vm_error = vm.execute(&chunk).unwrap_err().to_string();

    for runtime_error in [&tree_error, &vm_error] {
        assert!(runtime_error.contains("下界小于上界"), "{runtime_error}");
        assert!(
            runtime_error.contains("<标准库错误规格>:1"),
            "{runtime_error}"
        );
    }
}

#[test]
fn baseline_standard_modules_are_fully_available_in_both_runtimes() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("yanxu-vm-stdlib-{unique}"));
    fs::create_dir_all(&root).unwrap();
    fs::write(root.join("资料.txt"), "天地玄黄").unwrap();
    let file = source_path(&root.join("资料.txt"));
    let source = format!(
        r#"
        引「标准:文字」为 文字；引「标准:数学」为 数学；
        引「标准:时间」为 时间；引「标准:文件」为 文件；
        引「标准:JSON」为 JSON；引「标准:测试」为 测试；
        言 文字.联结（文字.分割（「甲,乙,丙」，「,」），「-」）；
        言 文字.替换（「青青子衿」，「青青」，「悠悠」）；
        言 数学.最大（数学.下取整（3.9），数学.幂（2，1））；
        定 数据：典 为 JSON.解析（「{{\"名\":\"言序\",\"版\":7}}」）；
        言 数据【「名」】；言 JSON.序列化（【真，空，3】）；
        测试.相等（文字.修剪（「  善  」），「善」）；
        时间.等待（0）；
        言 文件.读取（「{file}」）；言 文件.存在（「{file}」）；
        "#
    );
    let (tree, vm) = execute_both(&source, &root);
    assert_eq!(tree, vm);
    assert_eq!(
        tree,
        [
            "甲-乙-丙",
            "悠悠子衿",
            "3",
            "言序",
            "[true,null,3.0]",
            "天地玄黄",
            "真"
        ]
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn network_standard_module_matches_both_runtimes() {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\n\xe5\x96\x84\xe5\x93\x89\r\n0\r\n\r\n")
                .unwrap();
        }
    });
    let source = format!(
        r#"
        引「标准:网络」为 网络；
        定 应：典<文,任意> 为 网络.请求（「GET」，「http://{address}/问」，「」，1000，64）；
        言 应【「正文」】；言 应【「状态」】；
        试 则 网络.请求（「GET」，「ftp://example.com」，「」，1000，64）；
        救 错 则 言 错.代码；言 错.类别；终
        "#
    );
    let (tree, vm) = execute_both(&source, Path::new("."));
    assert_eq!(tree, ["善哉", "200", "NET_URL", "网络"]);
    assert_eq!(tree, vm);
    server.join().unwrap();
}

#[test]
fn file_standard_module_mutations_match_in_isolated_directories() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!("yanxu-file-parity-{unique}"));
    let tree_root = root.join("tree");
    let vm_root = root.join("vm");
    fs::create_dir_all(&tree_root).unwrap();
    fs::create_dir_all(&vm_root).unwrap();
    let program = |directory: &Path| {
        let path = source_path(&directory.join("资料.txt"));
        let directory = source_path(directory);
        format!(
            r#"
            引「标准:文件」为 文件；
            文件.写入（「{path}」，「甲」）；
            文件.追加（「{path}」，「乙」）；
            言 文件.读取（「{path}」）；
            言 文件.存在（「{path}」）；
            言 文件.目录（「{directory}」）；
        "#
        )
    };
    let statements = yanxu::parse(&program(&tree_root)).unwrap();
    let mut interpreter = Interpreter::silent();
    interpreter
        .execute_in_directory(&statements, &tree_root)
        .unwrap();
    let vm_statements = yanxu::parse(&program(&vm_root)).unwrap();
    let chunk = bytecode::compile(&vm_statements).unwrap();
    let mut vm = Vm::silent();
    vm.execute_in_directory(&chunk, &vm_root).unwrap();

    assert_eq!(interpreter.output(), vm.output());
    assert_eq!(
        fs::read_to_string(tree_root.join("资料.txt")).unwrap(),
        "甲乙"
    );
    assert_eq!(
        fs::read_to_string(vm_root.join("资料.txt")).unwrap(),
        "甲乙"
    );
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn guarded_process_execution_matches_both_runtimes() {
    let executable = source_path(&std::env::current_exe().unwrap());
    let source = format!(
        "引「标准:进程」为 进程；定 结果 为 进程.执行（「{executable}」，【「--list」】，空，30000）；言 结果【「成功」】；言 结果【「状态」】；"
    );
    let statements = yanxu::parse(&source).unwrap();
    yanxu::type_checker::check(&statements).unwrap();
    let mut interpreter = Interpreter::silent();
    interpreter.execute(&statements).unwrap();
    let chunk = bytecode::compile(&statements).unwrap();
    let mut vm = Vm::silent();
    vm.execute(&chunk).unwrap();
    assert_eq!(interpreter.output(), &["真", "0"]);
    assert_eq!(interpreter.output(), vm.output());

    let permissions = yanxu::permissions::PermissionSet::sandboxed();
    let mut interpreter = Interpreter::silent_with_permissions(permissions.clone());
    assert!(interpreter.execute(&statements).is_err());
    let mut vm = Vm::silent_with_permissions(permissions);
    assert!(vm.execute(&chunk).is_err());
}

#[test]
fn async_tasks_cancellation_and_structured_join_match_both_runtimes() {
    let source = r#"
        异 法 倍增（值：数）：数 则 归 值 乘 2；终
        异 法 失败（）：数 则 抛「任务失败」；终
        定 甲：任务<数> 为 倍增（3）；
        言 任务状态（甲）；言 候 甲；言 候 甲；
        定 乙：任务<数> 为 倍增（4）；
        定 丙：任务<数> 为 倍增（5）；
        言 并候（【乙，丙】）；
        定 丁：任务<数> 为 倍增（6）；言 取消（丁）；言 任务状态（丁）；
        定 坏：任务<数> 为 失败（）；定 后：任务<数> 为 倍增（7）；
        试 则 并候（【坏，后】）；救 错 则 言 错.消息；终
        言 任务状态（后）；
        令 自工：任务<数>? 为 空；
        异 法 自候（）：数 则 归 候 自工；终
        置 自工 为 自候（）；
        试 则 言 候 自工；救 错 则 言 错.消息；终
    "#;
    let tokens = yanxu::lexer::scan_named(source, "<异步一致性>").unwrap();
    assert!(matches!(tokens[0].kind, yanxu::token::TokenKind::Async));
    let (tree, vm) = execute_both(source, Path::new("."));
    assert_eq!(tree, vm);
    assert_eq!(
        tree,
        [
            "待行",
            "6",
            "6",
            "【8，10】",
            "真",
            "取消",
            "任务失败",
            "取消",
            "任务正在运行，不可自相等候"
        ]
    );
}
