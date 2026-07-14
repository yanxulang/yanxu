use yanxu::budget::ExecutionBudget;
use yanxu::embed::{Backend, Engine, EngineConfig};
use yanxu::permissions::PermissionSet;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut config = EngineConfig::sandboxed(Backend::Bytecode);
    config.budget = ExecutionBudget::new(50_000, 64, 10_000);
    config.permissions = PermissionSet::sandboxed();
    let mut engine = Engine::new(config);

    let first = engine.run("令 答案：数 为 40；")?;
    assert_eq!(first.value_type, "数");
    let second = engine.run("置 答案 为 答案 加 2；言 答案；")?;
    println!("{}", second.output.join("\n"));
    Ok(())
}
