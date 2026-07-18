use yanxu::budget::{ExecutionBudget, HostResourceLimits};
use yanxu::embed::{Backend, Engine, EngineConfig};
use yanxu::permissions::PermissionSet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = EngineConfig::sandboxed(Backend::Bytecode);
    config.budget = ExecutionBudget::new(50_000, 64, 10_000);
    config.permissions = PermissionSet::sandboxed();
    let mut engine = Engine::new(config);
    engine.set_host_resource_limits(
        HostResourceLimits::new(8 * 1024 * 1024, 8 * 1024 * 1024, 1024 * 1024)
            .expect("宿主资源上限有效"),
    );

    let first = engine.run("令 答案：数 为 40；")?;
    assert_eq!(first.value_type, "数");
    let second = engine.run("置 答案 为 答案 加 2；言 答案；")?;
    println!("{}", second.output.join("\n"));
    Ok(())
}
