//! 两套执行器共享的资源预算配置与计量器。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionBudget {
    pub max_steps: u64,
    pub max_call_depth: usize,
    pub max_collection_elements: usize,
}

impl ExecutionBudget {
    pub const fn new(
        max_steps: u64,
        max_call_depth: usize,
        max_collection_elements: usize,
    ) -> Self {
        Self {
            max_steps,
            max_call_depth,
            max_collection_elements,
        }
    }

    pub const fn unlimited() -> Self {
        Self::new(u64::MAX, usize::MAX, usize::MAX)
    }
}

impl Default for ExecutionBudget {
    fn default() -> Self {
        Self::new(1_000_000, 256, 100_000)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResourceMeter {
    budget: ExecutionBudget,
    steps: u64,
    call_depth: usize,
}

impl ResourceMeter {
    pub(crate) fn new(budget: ExecutionBudget) -> Self {
        Self {
            budget,
            steps: 0,
            call_depth: 0,
        }
    }

    pub(crate) fn budget(&self) -> ExecutionBudget {
        self.budget
    }

    pub(crate) fn set_budget(&mut self, budget: ExecutionBudget) {
        self.budget = budget;
        self.reset();
    }

    pub(crate) fn reset(&mut self) {
        self.steps = 0;
        self.call_depth = 0;
    }

    pub(crate) fn charge_step(&mut self) -> Result<(), String> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.budget.max_steps {
            Err(format!(
                "执行步数超过预算 {}；可提高 max_steps 或检查无穷循环",
                self.budget.max_steps
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn enter_call(&mut self) -> Result<(), String> {
        self.call_depth = self.call_depth.saturating_add(1);
        if self.call_depth > self.budget.max_call_depth {
            self.call_depth = self.call_depth.saturating_sub(1);
            Err(format!(
                "法调用深度超过预算 {}；可提高 max_call_depth 或检查递归终止条件",
                self.budget.max_call_depth
            ))
        } else {
            Ok(())
        }
    }

    pub(crate) fn leave_call(&mut self) {
        self.call_depth = self.call_depth.saturating_sub(1);
    }

    pub(crate) fn check_collection(&self, length: usize) -> Result<(), String> {
        if length > self.budget.max_collection_elements {
            Err(format!(
                "集合元素数 {length} 超过预算 {}；可提高 max_collection_elements 或分批处理数据",
                self.budget.max_collection_elements
            ))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meter_reports_actionable_limits_and_resets() {
        let mut meter = ResourceMeter::new(ExecutionBudget::new(1, 1, 1));
        assert!(meter.charge_step().is_ok());
        assert!(meter.charge_step().unwrap_err().contains("max_steps"));
        meter.reset();
        assert!(meter.charge_step().is_ok());
        assert!(meter.enter_call().is_ok());
        assert!(meter.enter_call().unwrap_err().contains("max_call_depth"));
        meter.leave_call();
        assert!(meter.check_collection(2).unwrap_err().contains("分批"));
    }
}
