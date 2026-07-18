//! 两套执行器共享的资源预算配置与计量器。

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionBudget {
    pub max_steps: u64,
    pub max_call_depth: usize,
    pub max_collection_elements: usize,
}

pub(crate) const MAX_BYTE_VALUE_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_HTTP_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_SOCKET_READ_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostResourceLimits {
    max_byte_value_bytes: u64,
    max_http_response_bytes: u64,
    max_socket_read_bytes: u64,
}

impl HostResourceLimits {
    #[cfg(test)]
    pub(crate) fn new(
        max_byte_value_bytes: u64,
        max_http_response_bytes: u64,
        max_socket_read_bytes: u64,
    ) -> Result<Self, String> {
        if !(1..=MAX_BYTE_VALUE_BYTES).contains(&max_byte_value_bytes) {
            return Err(format!(
                "宿主字节值上限须在 1..={MAX_BYTE_VALUE_BYTES} 字节之间"
            ));
        }
        if !(1..=MAX_HTTP_RESPONSE_BYTES).contains(&max_http_response_bytes)
            || max_http_response_bytes > max_byte_value_bytes
        {
            return Err(format!(
                "宿主 HTTP 响应上限须在 1..={MAX_HTTP_RESPONSE_BYTES} 字节之间，且不得超过字节值上限"
            ));
        }
        if !(1..=MAX_SOCKET_READ_BYTES).contains(&max_socket_read_bytes)
            || max_socket_read_bytes > max_byte_value_bytes
        {
            return Err(format!(
                "宿主套接字单次读取上限须在 1..={MAX_SOCKET_READ_BYTES} 字节之间，且不得超过字节值上限"
            ));
        }
        Ok(Self {
            max_byte_value_bytes,
            max_http_response_bytes,
            max_socket_read_bytes,
        })
    }

    pub(crate) const fn max_byte_value_bytes(self) -> u64 {
        self.max_byte_value_bytes
    }

    pub(crate) const fn max_socket_read_bytes(self) -> u64 {
        self.max_socket_read_bytes
    }

    #[cfg(not(target_family = "wasm"))]
    pub(crate) const fn effective_http_response_bytes(self, requested: u64) -> u64 {
        if requested < self.max_http_response_bytes {
            requested
        } else {
            self.max_http_response_bytes
        }
    }
}

impl Default for HostResourceLimits {
    fn default() -> Self {
        Self {
            max_byte_value_bytes: MAX_BYTE_VALUE_BYTES,
            max_http_response_bytes: MAX_HTTP_RESPONSE_BYTES,
            max_socket_read_bytes: MAX_SOCKET_READ_BYTES,
        }
    }
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
    host_limits: HostResourceLimits,
    steps: u64,
    call_depth: usize,
}

impl ResourceMeter {
    pub(crate) fn new(budget: ExecutionBudget) -> Self {
        Self {
            budget,
            host_limits: HostResourceLimits::default(),
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

    pub(crate) fn host_limits(&self) -> HostResourceLimits {
        self.host_limits
    }

    pub(crate) fn set_host_limits(&mut self, host_limits: HostResourceLimits) {
        self.host_limits = host_limits;
    }

    pub(crate) fn reset(&mut self) {
        self.steps = 0;
        self.call_depth = 0;
    }

    /// 进入一个独立计量的步数窗口（如宿主事件回调）：暂存累计步数并清零。
    /// 返回值必须交还给 `close_step_window`，以恢复外层执行的余额。
    pub(crate) fn open_step_window(&mut self) -> u64 {
        std::mem::take(&mut self.steps)
    }

    pub(crate) fn close_step_window(&mut self, saved_steps: u64) {
        self.steps = saved_steps;
    }

    pub(crate) fn charge_step(&mut self) -> Result<(), String> {
        self.steps = self.steps.saturating_add(1);
        if self.steps > self.budget.max_steps {
            Err(format!(
                "执行步数超过预算 {}；可提高 max_steps（命令行 --max-steps 或环境变量 YANXU_MAX_STEPS），或检查无穷循环",
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

    #[test]
    fn step_window_isolates_callback_budget_and_restores_outer_steps() {
        let mut meter = ResourceMeter::new(ExecutionBudget::new(2, 8, 8));
        assert!(meter.charge_step().is_ok());
        assert!(meter.charge_step().is_ok());
        // 外层余额已耗尽；窗口内应重新获得完整预算。
        let saved = meter.open_step_window();
        assert!(meter.charge_step().is_ok());
        assert!(meter.charge_step().is_ok());
        assert!(meter.charge_step().is_err());
        meter.close_step_window(saved);
        // 恢复后外层余额保持耗尽状态，不因窗口而放宽。
        assert!(meter.charge_step().is_err());
    }

    #[test]
    fn host_limits_are_ordered_bounded_and_can_only_tighten_requests() {
        let limits = HostResourceLimits::new(8 * 1024 * 1024, 6 * 1024 * 1024, 1024).unwrap();
        assert_eq!(limits.max_byte_value_bytes(), 8 * 1024 * 1024);
        assert_eq!(limits.effective_http_response_bytes(4 * 1024), 4 * 1024);
        assert_eq!(
            limits.effective_http_response_bytes(8 * 1024 * 1024),
            6 * 1024 * 1024
        );
        assert!(HostResourceLimits::new(0, 1, 1).is_err());
        assert!(HostResourceLimits::new(1024, 2048, 1).is_err());
        assert!(HostResourceLimits::new(1024, 1024, 2048).is_err());
        assert!(
            HostResourceLimits::new(
                MAX_BYTE_VALUE_BYTES + 1,
                MAX_HTTP_RESPONSE_BYTES,
                MAX_SOCKET_READ_BYTES,
            )
            .is_err()
        );
    }
}
