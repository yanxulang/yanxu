//! 持久回调与原生资源的 generation 句柄表。

use crate::host_events::{
    BoundedHostEventLoop, HostEvent, HostEventError, HostEventLoop, HostValue,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};
use std::thread::{self, ThreadId};

const MAX_GENERATION: u32 = u32::MAX;

fn encode_handle(index: usize, generation: u32) -> u64 {
    ((generation as u64) << 32) | (index as u64 + 1)
}

fn decode_handle(handle: u64) -> Option<(usize, u32)> {
    let encoded_index = handle as u32;
    let generation = (handle >> 32) as u32;
    if encoded_index == 0 || generation == 0 {
        None
    } else {
        Some((encoded_index as usize - 1, generation))
    }
}

fn next_generation(generation: u32) -> u32 {
    if generation == MAX_GENERATION {
        1
    } else {
        generation + 1
    }
}

struct CallbackEntry<T> {
    callback: T,
    references: u32,
}

struct CallbackSlot<T> {
    generation: u32,
    entry: Option<CallbackEntry<T>>,
}

#[derive(Clone)]
pub struct CallbackValidity {
    live: Arc<Mutex<HashSet<u64>>>,
}

impl CallbackValidity {
    pub fn is_live(&self, callback: u64) -> bool {
        self.live
            .lock()
            .expect("callback validity poisoned")
            .contains(&callback)
    }

    pub fn post(
        &self,
        event_loop: &BoundedHostEventLoop,
        callback: u64,
        arguments: Vec<HostValue>,
    ) -> Result<(), HostEventError> {
        if !self.is_live(callback) {
            return Err(HostEventError::new(
                "GUI_CALLBACK_RELEASED",
                "回调句柄已经释放或 generation 已失效",
            ));
        }
        event_loop.post(HostEvent::Callback {
            callback,
            arguments,
        })
    }
}

pub struct CallbackRegistry<T: Clone> {
    owner_thread: ThreadId,
    slots: Vec<CallbackSlot<T>>,
    free: Vec<usize>,
    live: Arc<Mutex<HashSet<u64>>>,
    closed: bool,
}

impl<T: Clone> CallbackRegistry<T> {
    pub fn new() -> Self {
        Self {
            owner_thread: thread::current().id(),
            slots: Vec::new(),
            free: Vec::new(),
            live: Arc::new(Mutex::new(HashSet::new())),
            closed: false,
        }
    }

    pub fn validity(&self) -> CallbackValidity {
        CallbackValidity {
            live: self.live.clone(),
        }
    }

    pub fn create(&mut self, callback: T) -> Result<u64, HostEventError> {
        self.assert_owner_thread()?;
        if self.closed {
            return Err(HostEventError::new(
                "GUI_EVENT_LOOP_CLOSED",
                "应用已经退出，不能创建回调",
            ));
        }
        let index = if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index];
            slot.generation = next_generation(slot.generation);
            slot.entry = Some(CallbackEntry {
                callback,
                references: 1,
            });
            index
        } else {
            self.slots.push(CallbackSlot {
                generation: 1,
                entry: Some(CallbackEntry {
                    callback,
                    references: 1,
                }),
            });
            self.slots.len() - 1
        };
        let handle = encode_handle(index, self.slots[index].generation);
        self.live
            .lock()
            .expect("callback validity poisoned")
            .insert(handle);
        Ok(handle)
    }

    pub fn retain(&mut self, handle: u64) -> Result<(), HostEventError> {
        self.assert_owner_thread()?;
        let entry = self.entry_mut(handle)?;
        entry.references = entry
            .references
            .checked_add(1)
            .ok_or_else(|| HostEventError::new("GUI_CALLBACK_LIMIT", "回调引用计数超过上限"))?;
        Ok(())
    }

    pub fn release(&mut self, handle: u64) -> Result<(), HostEventError> {
        self.assert_owner_thread()?;
        let Some((index, generation)) = decode_handle(handle) else {
            return Err(callback_released());
        };
        let slot = self.slots.get_mut(index).ok_or_else(callback_released)?;
        if slot.generation != generation {
            return Err(callback_released());
        }
        let entry = slot.entry.as_mut().ok_or_else(callback_released)?;
        entry.references -= 1;
        if entry.references == 0 {
            slot.entry.take();
            self.free.push(index);
            self.live
                .lock()
                .expect("callback validity poisoned")
                .remove(&handle);
        }
        Ok(())
    }

    pub fn get(&self, handle: u64) -> Result<T, HostEventError> {
        self.assert_owner_thread()?;
        let Some((index, generation)) = decode_handle(handle) else {
            return Err(callback_released());
        };
        let slot = self.slots.get(index).ok_or_else(callback_released)?;
        if slot.generation != generation {
            return Err(callback_released());
        }
        slot.entry
            .as_ref()
            .map(|entry| entry.callback.clone())
            .ok_or_else(callback_released)
    }

    pub fn live_count(&self) -> usize {
        self.live.lock().expect("callback validity poisoned").len()
    }

    pub fn close(&mut self) -> Result<(), HostEventError> {
        self.assert_owner_thread()?;
        self.closed = true;
        for slot in &mut self.slots {
            slot.entry.take();
        }
        self.free = (0..self.slots.len()).collect();
        self.live
            .lock()
            .expect("callback validity poisoned")
            .clear();
        Ok(())
    }

    fn entry_mut(&mut self, handle: u64) -> Result<&mut CallbackEntry<T>, HostEventError> {
        let Some((index, generation)) = decode_handle(handle) else {
            return Err(callback_released());
        };
        let slot = self.slots.get_mut(index).ok_or_else(callback_released)?;
        if slot.generation != generation {
            return Err(callback_released());
        }
        slot.entry.as_mut().ok_or_else(callback_released)
    }

    fn assert_owner_thread(&self) -> Result<(), HostEventError> {
        if thread::current().id() == self.owner_thread {
            Ok(())
        } else {
            Err(HostEventError::new(
                "GUI_WRONG_THREAD",
                "回调保留和释放只能在 VM 所属线程进行",
            ))
        }
    }
}

impl<T: Clone> Default for CallbackRegistry<T> {
    fn default() -> Self {
        Self::new()
    }
}

fn callback_released() -> HostEventError {
    HostEventError::new(
        "GUI_CALLBACK_RELEASED",
        "回调句柄已经释放或 generation 已失效",
    )
}

type ResourceDestructor = Box<dyn FnOnce()>;

struct ResourceEntry {
    type_name: String,
    extension: String,
    event_loop: u64,
    parent: Option<u64>,
    children: BTreeSet<u64>,
    raw_pointer: usize,
    destructor: Option<ResourceDestructor>,
}

struct ResourceSlot {
    generation: u32,
    entry: Option<ResourceEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceInfo {
    pub handle: u64,
    pub type_name: String,
    pub extension: String,
    pub event_loop: u64,
    pub parent: Option<u64>,
    pub children: Vec<u64>,
    pub owner_thread: ThreadId,
}

pub struct ResourceRegistry {
    owner_thread: ThreadId,
    event_loop: u64,
    slots: Vec<ResourceSlot>,
    free: Vec<usize>,
    live: usize,
}

impl ResourceRegistry {
    pub fn new(event_loop: u64) -> Self {
        Self {
            owner_thread: thread::current().id(),
            event_loop,
            slots: Vec::new(),
            free: Vec::new(),
            live: 0,
        }
    }

    pub fn create(
        &mut self,
        type_name: impl Into<String>,
        extension: impl Into<String>,
        parent: Option<u64>,
        destructor: impl FnOnce() + 'static,
    ) -> Result<u64, HostEventError> {
        self.create_native(type_name, extension, parent, 0, destructor)
    }

    pub fn create_native(
        &mut self,
        type_name: impl Into<String>,
        extension: impl Into<String>,
        parent: Option<u64>,
        raw_pointer: usize,
        destructor: impl FnOnce() + 'static,
    ) -> Result<u64, HostEventError> {
        self.assert_owner_thread()?;
        if let Some(parent) = parent {
            self.entry(parent)?;
        }
        let index = if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index];
            slot.generation = next_generation(slot.generation);
            index
        } else {
            self.slots.push(ResourceSlot {
                generation: 1,
                entry: None,
            });
            self.slots.len() - 1
        };
        let handle = encode_handle(index, self.slots[index].generation);
        self.slots[index].entry = Some(ResourceEntry {
            type_name: type_name.into(),
            extension: extension.into(),
            event_loop: self.event_loop,
            parent,
            children: BTreeSet::new(),
            raw_pointer,
            destructor: Some(Box::new(destructor)),
        });
        if let Some(parent) = parent {
            self.entry_mut(parent)?.children.insert(handle);
        }
        self.live += 1;
        Ok(handle)
    }

    pub fn info(&self, handle: u64) -> Result<ResourceInfo, HostEventError> {
        self.assert_owner_thread()?;
        let entry = self.entry(handle)?;
        Ok(ResourceInfo {
            handle,
            type_name: entry.type_name.clone(),
            extension: entry.extension.clone(),
            event_loop: entry.event_loop,
            parent: entry.parent,
            children: entry.children.iter().copied().collect(),
            owner_thread: self.owner_thread,
        })
    }

    pub fn assert_access(&self, handle: u64, event_loop: u64) -> Result<(), HostEventError> {
        self.assert_owner_thread()?;
        let entry = self.entry(handle)?;
        if entry.event_loop != event_loop {
            return Err(HostEventError::new(
                "GUI_WRONG_THREAD",
                "资源不属于当前宿主事件循环",
            ));
        }
        Ok(())
    }

    pub fn raw_pointer(
        &self,
        handle: u64,
        extension: &str,
    ) -> Result<*mut std::ffi::c_void, HostEventError> {
        self.assert_owner_thread()?;
        let entry = self.entry(handle)?;
        if entry.extension != extension {
            return Err(HostEventError::new(
                "GUI_RESOURCE_OWNER",
                "原生资源不属于请求它的扩展",
            ));
        }
        if entry.raw_pointer == 0 {
            return Err(HostEventError::new(
                "GUI_RESOURCE_CLOSED",
                "原生资源没有可用的底层指针",
            ));
        }
        Ok(entry.raw_pointer as *mut std::ffi::c_void)
    }

    pub fn close(&mut self, handle: u64) -> Result<(), HostEventError> {
        self.assert_owner_thread()?;
        let children = self
            .entry(handle)?
            .children
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>();
        let mut first_error = None;
        for child in children {
            if let Err(error) = self.close(child)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        let (index, generation) = decode_handle(handle).ok_or_else(resource_closed)?;
        let slot = self.slots.get_mut(index).ok_or_else(resource_closed)?;
        if slot.generation != generation {
            return Err(resource_closed());
        }
        let mut entry = slot.entry.take().ok_or_else(resource_closed)?;
        if let Some(parent) = entry.parent
            && let Ok(parent_entry) = self.entry_mut(parent)
        {
            parent_entry.children.remove(&handle);
        }
        self.free.push(index);
        self.live = self.live.saturating_sub(1);
        if let Some(destructor) = entry.destructor.take()
            && catch_unwind(AssertUnwindSafe(destructor)).is_err()
            && first_error.is_none()
        {
            first_error = Some(HostEventError::new(
                "GUI_RESOURCE_DROP_PANIC",
                "原生资源析构发生 panic；panic 已隔离在边界内",
            ));
        }
        first_error.map_or(Ok(()), Err)
    }

    pub fn close_all(&mut self) -> Result<(), HostEventError> {
        self.assert_owner_thread()?;
        let roots = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot.entry
                    .as_ref()
                    .filter(|entry| entry.parent.is_none())
                    .map(|_| encode_handle(index, slot.generation))
            })
            .collect::<Vec<_>>();
        let mut first_error = None;
        for root in roots.into_iter().rev() {
            if let Err(error) = self.close(root)
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    pub fn live_count(&self) -> usize {
        self.live
    }

    pub fn leak_statistics(&self) -> BTreeMap<String, usize> {
        let mut statistics = BTreeMap::new();
        for entry in self.slots.iter().filter_map(|slot| slot.entry.as_ref()) {
            *statistics.entry(entry.type_name.clone()).or_insert(0) += 1;
        }
        statistics
    }

    fn entry(&self, handle: u64) -> Result<&ResourceEntry, HostEventError> {
        let (index, generation) = decode_handle(handle).ok_or_else(resource_closed)?;
        let slot = self.slots.get(index).ok_or_else(resource_closed)?;
        if slot.generation != generation {
            return Err(resource_closed());
        }
        slot.entry.as_ref().ok_or_else(resource_closed)
    }

    fn entry_mut(&mut self, handle: u64) -> Result<&mut ResourceEntry, HostEventError> {
        let (index, generation) = decode_handle(handle).ok_or_else(resource_closed)?;
        let slot = self.slots.get_mut(index).ok_or_else(resource_closed)?;
        if slot.generation != generation {
            return Err(resource_closed());
        }
        slot.entry.as_mut().ok_or_else(resource_closed)
    }

    fn assert_owner_thread(&self) -> Result<(), HostEventError> {
        if thread::current().id() == self.owner_thread {
            Ok(())
        } else {
            Err(HostEventError::new(
                "GUI_WRONG_THREAD",
                "GUI 资源只能在所属线程操作或析构",
            ))
        }
    }
}

impl Drop for ResourceRegistry {
    fn drop(&mut self) {
        if thread::current().id() == self.owner_thread {
            let _ = self.close_all();
        }
    }
}

fn resource_closed() -> HostEventError {
    HostEventError::new(
        "GUI_RESOURCE_CLOSED",
        "原生资源已经关闭或 generation 已失效",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn callback_generation_rejects_stale_handles_and_keeps_captures_alive() {
        let mut registry = CallbackRegistry::new();
        let captured = Arc::new(String::from("捕获环境"));
        let first = registry.create(captured.clone()).unwrap();
        registry.retain(first).unwrap();
        registry.release(first).unwrap();
        assert_eq!(registry.get(first).unwrap().as_str(), "捕获环境");
        registry.release(first).unwrap();
        assert_eq!(
            registry.get(first).unwrap_err().code,
            "GUI_CALLBACK_RELEASED"
        );
        let second = registry.create(Arc::new(String::from("新闭包"))).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            registry.get(first).unwrap_err().code,
            "GUI_CALLBACK_RELEASED"
        );
    }

    #[test]
    fn background_threads_can_only_post_live_callbacks() {
        let event_loop = BoundedHostEventLoop::default();
        let mut registry = CallbackRegistry::new();
        let callback = registry.create(7_u8).unwrap();
        let validity = registry.validity();
        let worker_loop = event_loop.clone();
        thread::spawn(move || {
            validity
                .post(&worker_loop, callback, vec![HostValue::Integer(9)])
                .unwrap();
        })
        .join()
        .unwrap();
        assert!(matches!(
            event_loop.try_next().unwrap(),
            Some(HostEvent::Callback { callback: found, .. }) if found == callback
        ));
        registry.release(callback).unwrap();
        assert_eq!(
            registry
                .validity()
                .post(&event_loop, callback, Vec::new())
                .unwrap_err()
                .code,
            "GUI_CALLBACK_RELEASED"
        );
    }

    #[test]
    fn resource_tree_closes_children_before_parent_exactly_once() {
        let drops = Arc::new(Mutex::new(Vec::new()));
        let mut registry = ResourceRegistry::new(11);
        let parent_drops = drops.clone();
        let parent = registry
            .create("窗口", "gui", None, move || {
                parent_drops.lock().unwrap().push("窗口")
            })
            .unwrap();
        let child_drops = drops.clone();
        let child = registry
            .create("按钮", "gui", Some(parent), move || {
                child_drops.lock().unwrap().push("按钮")
            })
            .unwrap();
        assert_eq!(registry.info(parent).unwrap().children, vec![child]);
        registry.close(parent).unwrap();
        assert_eq!(*drops.lock().unwrap(), vec!["按钮", "窗口"]);
        assert_eq!(registry.live_count(), 0);
        assert_eq!(
            registry.close(parent).unwrap_err().code,
            "GUI_RESOURCE_CLOSED"
        );
        assert_eq!(
            registry.info(child).unwrap_err().code,
            "GUI_RESOURCE_CLOSED"
        );
    }

    #[test]
    fn resource_drop_panics_are_isolated_and_registry_reaches_zero() {
        static DROPS: AtomicUsize = AtomicUsize::new(0);
        let mut registry = ResourceRegistry::new(1);
        let resource = registry
            .create("测试", "extension", None, || {
                DROPS.fetch_add(1, Ordering::SeqCst);
                panic!("destructor panic")
            })
            .unwrap();
        assert_eq!(
            registry.close(resource).unwrap_err().code,
            "GUI_RESOURCE_DROP_PANIC"
        );
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
        assert_eq!(registry.live_count(), 0);
    }
}
