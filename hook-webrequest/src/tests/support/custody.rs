use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

#[derive(Clone, Copy, Debug, Default)]
pub struct Payload {
    address: usize,
    pub len: usize,
    pub freed: bool,
    pub reallocated: bool,
    pub bytes_read: usize,
    pub wiped: bool,
}
#[derive(Clone, Copy)]
struct State {
    active: bool,
    entries: [Payload; 32],
    used: usize,
    /// While nonzero, every allocation of exactly this many bytes is registered.
    armed: usize,
}
thread_local! {
    static STATE: Cell<State> = const { Cell::new(State {
        active: false,
        entries: [Payload { address: 0, len: 0, freed: false, reallocated: false,
            bytes_read: 0, wiped: false }; 32],
        used: 0,
        armed: 0,
    }) };
}

#[derive(Default)]
pub struct CustodyAllocator;
impl CustodyAllocator {
    pub const fn new() -> Self {
        Self
    }
}

// SAFETY: every allocation operation delegates to System with its original arguments.
// Observation performs no allocation and reads only initialized bytes registered by an
// exclusive owner on this thread before System releases its live allocation.
unsafe impl GlobalAlloc for CustodyAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: GlobalAlloc caller supplies a valid layout.
        let ptr = unsafe { System.alloc(layout) };
        note_allocation(ptr, layout.size());
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: ptr still names its live allocation until System.dealloc below.
        unsafe { observe(ptr, false) };
        // SAFETY: forwards the original live allocation and layout unchanged.
        unsafe { System.dealloc(ptr, layout) };
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: ptr still names its live allocation until System.realloc below.
        unsafe { observe(ptr, true) };
        // SAFETY: forwards the allocator's original valid arguments.
        unsafe { System.realloc(ptr, layout, size) }
    }
}

unsafe fn observe(ptr: *mut u8, realloc: bool) {
    let _ = STATE.try_with(|cell| {
        let mut state = cell.get();
        if !state.active {
            return;
        }
        for entry in &mut state.entries[..state.used] {
            if entry.address != ptr as usize || entry.freed || entry.reallocated {
                continue;
            }
            // SAFETY: watch_owner_prefix's contract guarantees this allocation's
            // initialized prefix remains exclusively owned until this deallocation hook.
            entry.wiped = true;
            for offset in 0..entry.len {
                // SAFETY: offset stays inside the registered initialized allocation prefix.
                entry.wiped &= unsafe { ptr.add(offset).read_volatile() } == 0;
                entry.bytes_read += 1;
            }
            entry.freed = !realloc;
            entry.reallocated = realloc;
        }
        cell.set(state);
    });
}

/// Register `ptr` when an armed watch ([`watch_allocations_of`]) asks for allocations of `size`.
fn note_allocation(ptr: *mut u8, size: usize) {
    let _ = STATE.try_with(|cell| {
        let mut state = cell.get();
        if !state.active
            || size == 0
            || state.armed != size
            || ptr.is_null()
            || state.used >= state.entries.len()
        {
            return;
        }
        state.entries[state.used] = Payload {
            address: ptr as usize,
            len: size,
            ..Payload::default()
        };
        state.used += 1;
        cell.set(state);
    });
}

/// Register every allocation of exactly `size` bytes this thread makes from now until
/// [`stop_watching`], as [`watch_owner_prefix`] registers one.
///
/// # Safety
/// Every such allocation must be fully initialized and exclusively owned on this thread when it
/// is freed or reallocated.
pub unsafe fn watch_allocations_of(size: usize) {
    STATE.with(|cell| {
        let mut state = cell.get();
        assert!(state.active && size != 0);
        state.armed = size;
        cell.set(state);
    });
}

/// End [`watch_allocations_of`].
pub fn stop_watching() {
    STATE.with(|cell| {
        let mut state = cell.get();
        state.armed = 0;
        cell.set(state);
    });
}

pub struct OwnerProbe;
#[derive(Debug)]
pub struct Observations {
    pub payloads: Vec<Payload>,
}
impl OwnerProbe {
    /// # Safety
    /// Registrations must uphold watch_owner_prefix's exclusive owner contract.
    pub unsafe fn start() -> Result<Self, &'static str> {
        STATE.with(|cell| {
            let mut state = cell.get();
            if state.active {
                return Err("nested custody probe");
            }
            state.active = true;
            state.used = 0;
            state.armed = 0;
            cell.set(state);
            Ok(Self)
        })
    }
    pub fn finish(self) -> Observations {
        let state = STATE.with(|cell| {
            let mut state = cell.get();
            state.active = false;
            state.armed = 0;
            cell.set(state);
            state
        });
        Observations {
            payloads: state.entries[..state.used].to_vec(),
        }
    }
}
impl Drop for OwnerProbe {
    fn drop(&mut self) {
        let _ = STATE.try_with(|cell| {
            let mut s = cell.get();
            s.active = false;
            s.armed = 0;
            cell.set(s);
        });
    }
}

/// # Safety
/// Bytes names the complete initialized prefix at an owned allocation base.
/// The owner must stay exclusively on this thread until it drops or reallocates.
pub unsafe fn watch_owner_prefix(bytes: &[u8]) {
    STATE.with(|cell| {
        let mut state = cell.get();
        assert!(state.active && state.used < state.entries.len());
        state.entries[state.used] = Payload {
            address: bytes.as_ptr() as usize,
            len: bytes.len(),
            ..Payload::default()
        };
        state.used += 1;
        cell.set(state);
    });
}
