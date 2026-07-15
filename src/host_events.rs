//! VM 与原生宿主之间的有界事件队列。
//!
//! 后台线程只能把拥有所有权的 [`HostEvent`] 投递到队列；只有创建队列的
//! 线程可以取出事件并进入 VM。鼠标移动和窗口缩放等连续状态在队列中的原
//! 位置更新，因此不会破坏普通事件的先后次序，也不会因输入频率耗尽内存。

use std::collections::VecDeque;
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::thread::{self, JoinHandle, ThreadId};
use std::time::Duration;

pub const DEFAULT_HOST_EVENT_CAPACITY: usize = 4_096;
pub const MIN_TIMER_INTERVAL: Duration = Duration::from_millis(10);
pub const MAX_TIMER_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
static NEXT_EVENT_LOOP_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_TIMER_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq)]
pub enum HostValue {
    Nil,
    Bool(bool),
    Integer(i64),
    Number(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<HostValue>),
    Map(Vec<(HostValue, HostValue)>),
    Resource(u64),
    Callback(u64),
    Error {
        code: String,
        message: String,
        details: Option<Box<HostValue>>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostValueLimits {
    pub max_depth: usize,
    pub max_elements: usize,
    pub max_total_bytes: usize,
    pub max_string_bytes: usize,
    pub max_byte_string_bytes: usize,
}

impl Default for HostValueLimits {
    fn default() -> Self {
        Self {
            max_depth: 64,
            max_elements: 65_536,
            max_total_bytes: 16 * 1024 * 1024,
            max_string_bytes: 4 * 1024 * 1024,
            max_byte_string_bytes: 16 * 1024 * 1024,
        }
    }
}

impl HostValue {
    pub fn validate(&self, limits: HostValueLimits) -> Result<(), HostEventError> {
        let mut stats = HostValueStats::default();
        validate_value(self, limits, 0, &mut stats)
    }
}

#[derive(Default)]
struct HostValueStats {
    elements: usize,
    bytes: usize,
}

fn validate_value(
    value: &HostValue,
    limits: HostValueLimits,
    depth: usize,
    stats: &mut HostValueStats,
) -> Result<(), HostEventError> {
    if depth > limits.max_depth {
        return Err(HostEventError::new(
            "NATIVE_VALUE_LIMIT",
            format!("类型化值递归深度不得超过 {}", limits.max_depth),
        ));
    }
    stats.elements = stats.elements.saturating_add(1);
    if stats.elements > limits.max_elements {
        return Err(HostEventError::new(
            "NATIVE_VALUE_LIMIT",
            format!("类型化值元素不得超过 {}", limits.max_elements),
        ));
    }
    let owned_bytes = match value {
        HostValue::String(text) => {
            if text.len() > limits.max_string_bytes {
                return Err(HostEventError::new(
                    "NATIVE_VALUE_LIMIT",
                    format!("文字不得超过 {} 字节", limits.max_string_bytes),
                ));
            }
            text.len()
        }
        HostValue::Bytes(bytes) => {
            if bytes.len() > limits.max_byte_string_bytes {
                return Err(HostEventError::new(
                    "NATIVE_VALUE_LIMIT",
                    format!("字节串不得超过 {} 字节", limits.max_byte_string_bytes),
                ));
            }
            bytes.len()
        }
        HostValue::Array(values) => {
            for value in values {
                validate_value(value, limits, depth + 1, stats)?;
            }
            0
        }
        HostValue::Map(entries) => {
            for (key, value) in entries {
                validate_value(key, limits, depth + 1, stats)?;
                validate_value(value, limits, depth + 1, stats)?;
            }
            0
        }
        HostValue::Error {
            code,
            message,
            details,
        } => {
            if code.len() > 256 || message.len() > 64 * 1024 {
                return Err(HostEventError::new(
                    "NATIVE_VALUE_LIMIT",
                    "结构化错误字段过长",
                ));
            }
            if let Some(details) = details {
                validate_value(details, limits, depth + 1, stats)?;
            }
            code.len().saturating_add(message.len())
        }
        HostValue::Nil
        | HostValue::Bool(_)
        | HostValue::Integer(_)
        | HostValue::Number(_)
        | HostValue::Resource(_)
        | HostValue::Callback(_) => 0,
    };
    stats.bytes = stats.bytes.saturating_add(owned_bytes);
    if stats.bytes > limits.max_total_bytes {
        return Err(HostEventError::new(
            "NATIVE_VALUE_LIMIT",
            format!("类型化值总内存不得超过 {} 字节", limits.max_total_bytes),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub enum HostEvent {
    Callback {
        callback: u64,
        arguments: Vec<HostValue>,
    },
    Timer {
        timer: u64,
        callback: Option<u64>,
    },
    MouseMove {
        resource: u64,
        x: f64,
        y: f64,
    },
    WindowResize {
        resource: u64,
        width: u32,
        height: u32,
    },
    Custom {
        name: String,
        payload: HostValue,
    },
    Wake,
    Quit,
}

impl HostEvent {
    fn same_coalescing_key(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::MouseMove { resource: left, .. },
                Self::MouseMove {
                    resource: right, ..
                },
            )
            | (
                Self::WindowResize { resource: left, .. },
                Self::WindowResize {
                    resource: right, ..
                },
            ) => left == right,
            (Self::Wake, Self::Wake) => true,
            _ => false,
        }
    }

    fn validates_payload(&self) -> Result<(), HostEventError> {
        match self {
            Self::Callback { arguments, .. } => {
                let aggregate = HostValue::Array(arguments.clone());
                aggregate.validate(HostValueLimits::default())
            }
            Self::Custom { name, payload } => {
                if name.is_empty() || name.len() > 1_024 {
                    return Err(HostEventError::new(
                        "NATIVE_VALUE_LIMIT",
                        "自定义事件名为空或过长",
                    ));
                }
                payload.validate(HostValueLimits::default())
            }
            _ => Ok(()),
        }
    }
}

pub trait HostEventLoop: Send + Sync {
    fn post(&self, event: HostEvent) -> Result<(), HostEventError>;
    fn wake(&self);
    fn quit(&self);
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEventError {
    pub code: &'static str,
    pub message: String,
}

impl HostEventError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl fmt::Display for HostEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for HostEventError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QueueLifecycle {
    Open,
    Running,
    Closed,
}

struct QueueState {
    lifecycle: QueueLifecycle,
    events: VecDeque<HostEvent>,
}

struct QueueInner {
    state: Mutex<QueueState>,
    available: Condvar,
    capacity: usize,
    owner_thread: ThreadId,
    id: u64,
}

#[derive(Clone)]
pub struct BoundedHostEventLoop {
    inner: Arc<QueueInner>,
}

impl BoundedHostEventLoop {
    pub fn new(capacity: usize) -> Result<Self, HostEventError> {
        if capacity == 0 {
            return Err(HostEventError::new(
                "GUI_QUEUE_CAPACITY",
                "宿主事件队列容量必须大于零",
            ));
        }
        Ok(Self {
            inner: Arc::new(QueueInner {
                state: Mutex::new(QueueState {
                    lifecycle: QueueLifecycle::Open,
                    events: VecDeque::with_capacity(capacity),
                }),
                available: Condvar::new(),
                capacity,
                owner_thread: thread::current().id(),
                id: NEXT_EVENT_LOOP_ID.fetch_add(1, Ordering::Relaxed),
            }),
        })
    }

    pub fn id(&self) -> u64 {
        self.inner.id
    }

    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }

    pub fn len(&self) -> usize {
        self.inner
            .state
            .lock()
            .expect("host event queue poisoned")
            .events
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn is_closed(&self) -> bool {
        self.inner
            .state
            .lock()
            .expect("host event queue poisoned")
            .lifecycle
            == QueueLifecycle::Closed
    }

    pub fn assert_owner_thread(&self) -> Result<(), HostEventError> {
        if thread::current().id() == self.inner.owner_thread {
            Ok(())
        } else {
            Err(HostEventError::new(
                "GUI_WRONG_THREAD",
                "只有创建 VM 的线程可以处理宿主事件",
            ))
        }
    }

    pub fn begin_run(&self) -> Result<HostEventRunGuard, HostEventError> {
        self.assert_owner_thread()?;
        let mut state = self.inner.state.lock().expect("host event queue poisoned");
        match state.lifecycle {
            QueueLifecycle::Open => state.lifecycle = QueueLifecycle::Running,
            QueueLifecycle::Running => {
                return Err(HostEventError::new(
                    "GUI_EVENT_LOOP_RUNNING",
                    "宿主事件循环已经运行",
                ));
            }
            QueueLifecycle::Closed => {
                return Err(HostEventError::new(
                    "GUI_EVENT_LOOP_CLOSED",
                    "宿主事件循环已经关闭",
                ));
            }
        }
        drop(state);
        Ok(HostEventRunGuard {
            event_loop: self.clone(),
            active: true,
        })
    }

    pub fn try_next(&self) -> Result<Option<HostEvent>, HostEventError> {
        self.assert_owner_thread()?;
        let mut state = self.inner.state.lock().expect("host event queue poisoned");
        if state.lifecycle == QueueLifecycle::Closed {
            return Err(HostEventError::new(
                "GUI_EVENT_LOOP_CLOSED",
                "宿主事件循环已经关闭",
            ));
        }
        Ok(state.events.pop_front())
    }

    pub fn wait_next(
        &self,
        timeout: Option<Duration>,
    ) -> Result<Option<HostEvent>, HostEventError> {
        self.assert_owner_thread()?;
        let mut state = self.inner.state.lock().expect("host event queue poisoned");
        while state.events.is_empty() && state.lifecycle != QueueLifecycle::Closed {
            state = if let Some(timeout) = timeout {
                let (state, result) = self
                    .inner
                    .available
                    .wait_timeout(state, timeout)
                    .expect("host event queue poisoned");
                if result.timed_out() {
                    return Ok(None);
                }
                state
            } else {
                self.inner
                    .available
                    .wait(state)
                    .expect("host event queue poisoned")
            };
        }
        if state.lifecycle == QueueLifecycle::Closed {
            return Err(HostEventError::new(
                "GUI_EVENT_LOOP_CLOSED",
                "宿主事件循环已经关闭",
            ));
        }
        Ok(state.events.pop_front())
    }

    fn finish_run(&self) {
        if thread::current().id() != self.inner.owner_thread {
            return;
        }
        let mut state = self.inner.state.lock().expect("host event queue poisoned");
        if state.lifecycle == QueueLifecycle::Running {
            state.lifecycle = QueueLifecycle::Open;
        }
    }
}

impl Default for BoundedHostEventLoop {
    fn default() -> Self {
        Self::new(DEFAULT_HOST_EVENT_CAPACITY).expect("default event capacity is valid")
    }
}

impl HostEventLoop for BoundedHostEventLoop {
    fn post(&self, event: HostEvent) -> Result<(), HostEventError> {
        event.validates_payload()?;
        let mut state = self.inner.state.lock().expect("host event queue poisoned");
        if state.lifecycle == QueueLifecycle::Closed {
            return Err(HostEventError::new(
                "GUI_EVENT_LOOP_CLOSED",
                "宿主事件循环已经关闭",
            ));
        }
        if let Some(index) = state
            .events
            .iter()
            .position(|queued| queued.same_coalescing_key(&event))
        {
            state.events[index] = event;
            self.inner.available.notify_one();
            return Ok(());
        }
        if state.events.len() >= self.inner.capacity {
            return Err(HostEventError::new(
                "GUI_QUEUE_FULL",
                format!("宿主事件队列已达到 {} 项上限", self.inner.capacity),
            ));
        }
        state.events.push_back(event);
        self.inner.available.notify_one();
        Ok(())
    }

    fn wake(&self) {
        let _ = self.post(HostEvent::Wake);
    }

    fn quit(&self) {
        let mut state = self.inner.state.lock().expect("host event queue poisoned");
        state.lifecycle = QueueLifecycle::Closed;
        state.events.clear();
        self.inner.available.notify_all();
    }
}

pub struct HostEventRunGuard {
    event_loop: BoundedHostEventLoop,
    active: bool,
}

impl HostEventRunGuard {
    pub fn finish(mut self) {
        if self.active {
            self.event_loop.finish_run();
            self.active = false;
        }
    }
}

impl Drop for HostEventRunGuard {
    fn drop(&mut self) {
        if self.active {
            self.event_loop.finish_run();
            self.active = false;
        }
    }
}

pub struct HostTimer {
    id: u64,
    cancellation: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<()>>,
    cancelled: Arc<AtomicBool>,
}

impl HostTimer {
    pub fn once(
        event_loop: BoundedHostEventLoop,
        interval: Duration,
        callback: Option<u64>,
    ) -> Result<Self, HostEventError> {
        Self::spawn(event_loop, interval, callback, false)
    }

    pub fn periodic(
        event_loop: BoundedHostEventLoop,
        interval: Duration,
        callback: Option<u64>,
    ) -> Result<Self, HostEventError> {
        Self::spawn(event_loop, interval, callback, true)
    }

    fn spawn(
        event_loop: BoundedHostEventLoop,
        interval: Duration,
        callback: Option<u64>,
        periodic: bool,
    ) -> Result<Self, HostEventError> {
        if !(MIN_TIMER_INTERVAL..=MAX_TIMER_INTERVAL).contains(&interval) {
            return Err(HostEventError::new(
                "GUI_TIMER_INTERVAL",
                format!(
                    "定时器间隔须在 {} 毫秒至 {} 毫秒之间",
                    MIN_TIMER_INTERVAL.as_millis(),
                    MAX_TIMER_INTERVAL.as_millis()
                ),
            ));
        }
        if event_loop.is_closed() {
            return Err(HostEventError::new(
                "GUI_EVENT_LOOP_CLOSED",
                "宿主事件循环已经关闭",
            ));
        }
        let id = NEXT_TIMER_ID.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let worker_cancelled = cancelled.clone();
        let worker = thread::Builder::new()
            .name(format!("yanxu-timer-{id}"))
            .spawn(move || {
                loop {
                    match receiver.recv_timeout(interval) {
                        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if event_loop
                                .post(HostEvent::Timer {
                                    timer: id,
                                    callback,
                                })
                                .is_err()
                                || !periodic
                            {
                                break;
                            }
                        }
                    }
                }
                worker_cancelled.store(true, Ordering::Release);
            })
            .map_err(|error| {
                HostEventError::new("GUI_TIMER_THREAD", format!("不能启动定时器：{error}"))
            })?;
        Ok(Self {
            id,
            cancellation: Some(sender),
            worker: Some(worker),
            cancelled,
        })
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    pub fn cancel(&mut self) {
        if let Some(sender) = self.cancellation.take() {
            let _ = sender.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.cancelled.store(true, Ordering::Release);
    }
}

impl Drop for HostTimer {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_queue_preserves_order_and_coalesces_continuous_events() {
        let event_loop = BoundedHostEventLoop::new(3).unwrap();
        event_loop
            .post(HostEvent::Custom {
                name: "first".into(),
                payload: HostValue::Nil,
            })
            .unwrap();
        event_loop
            .post(HostEvent::MouseMove {
                resource: 7,
                x: 1.0,
                y: 2.0,
            })
            .unwrap();
        event_loop
            .post(HostEvent::MouseMove {
                resource: 7,
                x: 3.0,
                y: 4.0,
            })
            .unwrap();
        event_loop
            .post(HostEvent::Custom {
                name: "last".into(),
                payload: HostValue::Nil,
            })
            .unwrap();
        assert_eq!(event_loop.len(), 3);
        assert!(matches!(
            event_loop.try_next().unwrap(),
            Some(HostEvent::Custom { name, .. }) if name == "first"
        ));
        assert!(matches!(
            event_loop.try_next().unwrap(),
            Some(HostEvent::MouseMove { x, y, .. }) if x == 3.0 && y == 4.0
        ));
        assert!(matches!(
            event_loop.try_next().unwrap(),
            Some(HostEvent::Custom { name, .. }) if name == "last"
        ));
    }

    #[test]
    fn bounded_queue_rejects_overflow_close_and_non_owner_consumers() {
        let event_loop = BoundedHostEventLoop::new(1).unwrap();
        event_loop.wake();
        assert_eq!(
            event_loop.post(HostEvent::Quit).unwrap_err().code,
            "GUI_QUEUE_FULL"
        );
        let worker_loop = event_loop.clone();
        let error = thread::spawn(move || worker_loop.try_next().unwrap_err())
            .join()
            .unwrap();
        assert_eq!(error.code, "GUI_WRONG_THREAD");
        event_loop.quit();
        assert_eq!(
            event_loop.post(HostEvent::Wake).unwrap_err().code,
            "GUI_EVENT_LOOP_CLOSED"
        );
    }

    #[test]
    fn run_guard_rejects_nested_runs_and_allows_a_later_run() {
        let event_loop = BoundedHostEventLoop::default();
        let guard = event_loop.begin_run().unwrap();
        let nested = match event_loop.begin_run() {
            Ok(_) => panic!("nested event loop should be rejected"),
            Err(error) => error,
        };
        assert_eq!(nested.code, "GUI_EVENT_LOOP_RUNNING");
        guard.finish();
        event_loop.begin_run().unwrap().finish();
    }

    #[test]
    fn timer_posts_once_and_cancellation_stops_periodic_delivery() {
        let event_loop = BoundedHostEventLoop::default();
        let mut timer = HostTimer::once(event_loop.clone(), MIN_TIMER_INTERVAL, Some(42)).unwrap();
        assert!(matches!(
            event_loop.wait_next(Some(Duration::from_secs(1))).unwrap(),
            Some(HostEvent::Timer {
                callback: Some(42),
                ..
            })
        ));
        timer.cancel();
        assert!(timer.is_cancelled());

        let mut periodic =
            HostTimer::periodic(event_loop.clone(), MIN_TIMER_INTERVAL, None).unwrap();
        assert!(
            event_loop
                .wait_next(Some(Duration::from_secs(1)))
                .unwrap()
                .is_some()
        );
        periodic.cancel();
        while event_loop.try_next().unwrap().is_some() {}
        assert!(
            event_loop
                .wait_next(Some(Duration::from_millis(25)))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn typed_values_enforce_depth_element_and_memory_limits() {
        let limits = HostValueLimits {
            max_depth: 2,
            max_elements: 4,
            max_total_bytes: 4,
            max_string_bytes: 4,
            max_byte_string_bytes: 4,
        };
        assert!(HostValue::String("言序".into()).validate(limits).is_err());
        assert!(
            HostValue::Array(vec![HostValue::Array(vec![HostValue::Array(vec![
                HostValue::Nil,
            ])])])
            .validate(limits)
            .is_err()
        );
    }
}
