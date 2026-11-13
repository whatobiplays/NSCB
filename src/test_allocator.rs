//! Deterministic, test-only refusal of tagged fallible reservations.

use crate::allocation::AllocationSite;
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

static ACTIVE_FAILPOINTS: AtomicUsize = AtomicUsize::new(0);

const NO_SITE: u8 = u8::MAX;

#[derive(Clone, Copy)]
struct State {
    tracking: bool,
    armed: bool,
    target_site: u8,
    target_occurrence: u32,
    site_calls: u32,
    active_site: u8,
    active_occurrence: u32,
    active_layout: Option<(usize, usize)>,
    expected_layout: Option<(usize, usize)>,
    refusal_count: u32,
    refused_site: u8,
    refused_occurrence: u32,
    requested_layout: Option<(usize, usize)>,
}

impl State {
    const EMPTY: Self = Self {
        tracking: false,
        armed: false,
        target_site: NO_SITE,
        target_occurrence: 0,
        site_calls: 0,
        active_site: NO_SITE,
        active_occurrence: 0,
        active_layout: None,
        expected_layout: None,
        refusal_count: 0,
        refused_site: NO_SITE,
        refused_occurrence: 0,
        requested_layout: None,
    };
}

thread_local! {
    static STATE: Cell<State> = const { Cell::new(State::EMPTY) };
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct Observation {
    pub(crate) target_site: u8,
    pub(crate) target_occurrence: u32,
    pub(crate) site_calls: u32,
    pub(crate) refusal_count: u32,
    pub(crate) refused_site: u8,
    pub(crate) refused_occurrence: u32,
    pub(crate) expected_layout: Option<(usize, usize)>,
    pub(crate) requested_layout: Option<(usize, usize)>,
    pub(crate) armed_on_finish: bool,
    pub(crate) tracking_started: bool,
}

impl Observation {
    pub(crate) fn is_exact_refusal(self, site: AllocationSite, occurrence: u32) -> bool {
        self.tracking_started
            && self.target_site == site as u8
            && self.target_occurrence == occurrence
            && self.site_calls >= occurrence
            && self.refusal_count == 1
            && self.refused_site == site as u8
            && self.refused_occurrence == occurrence
            && self.expected_layout.is_some()
            && self.requested_layout == self.expected_layout
            && !self.armed_on_finish
    }
}

pub(crate) struct TestAllocator;

unsafe impl GlobalAlloc for TestAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if should_refuse(layout) {
            ptr::null_mut()
        } else {
            unsafe { System.alloc(layout) }
        }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        if should_refuse(layout) {
            ptr::null_mut()
        } else {
            unsafe { System.alloc_zeroed(layout) }
        }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let requested = Layout::from_size_align(new_size, layout.align());
        if requested.is_ok_and(should_refuse) {
            ptr::null_mut()
        } else {
            unsafe { System.realloc(pointer, layout, new_size) }
        }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
    }
}

struct ArmGuard {
    tracking_started: bool,
}

impl Drop for ArmGuard {
    fn drop(&mut self) {
        if self.tracking_started {
            let _ = STATE.try_with(|state| state.set(State::EMPTY));
            ACTIVE_FAILPOINTS.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

struct SiteGuard {
    entered: bool,
}

impl Drop for SiteGuard {
    fn drop(&mut self) {
        if self.entered {
            let _ = STATE.try_with(|state| {
                let mut current = state.get();
                current.active_site = NO_SITE;
                current.active_occurrence = 0;
                current.active_layout = None;
                state.set(current);
            });
        }
    }
}

/// Refuses one tagged allocation and returns the callback's recorded evidence.
pub(crate) fn with_refusal<T>(
    site: AllocationSite,
    occurrence: u32,
    action: impl FnOnce() -> T,
) -> (T, Observation) {
    let tracking_started = STATE
        .try_with(|state| {
            if state.get().tracking || occurrence == 0 {
                return false;
            }
            state.set(State {
                tracking: true,
                armed: true,
                target_site: site as u8,
                target_occurrence: occurrence,
                ..State::EMPTY
            });
            true
        })
        .unwrap_or(false);

    if tracking_started {
        ACTIVE_FAILPOINTS.fetch_add(1, Ordering::Relaxed);
    }
    let guard = ArmGuard { tracking_started };
    let result = action();
    let observation = if tracking_started {
        STATE
            .try_with(|state| {
                let state = state.get();
                Observation {
                    target_site: state.target_site,
                    target_occurrence: state.target_occurrence,
                    site_calls: state.site_calls,
                    refusal_count: state.refusal_count,
                    refused_site: state.refused_site,
                    refused_occurrence: state.refused_occurrence,
                    expected_layout: state.expected_layout,
                    requested_layout: state.requested_layout,
                    armed_on_finish: state.armed,
                    tracking_started: true,
                }
            })
            .unwrap_or_default()
    } else {
        Observation::default()
    };
    drop(guard);
    (result, observation)
}

pub(crate) fn reserve_with_layout(
    site: AllocationSite,
    expected_layout: Option<Layout>,
    reserve: impl FnOnce() -> Result<(), std::collections::TryReserveError>,
) -> Result<(), std::collections::TryReserveError> {
    let expected_layout = expected_layout.map(|layout| (layout.size(), layout.align()));
    let entered = STATE
        .try_with(|state| {
            let mut current = state.get();
            if !current.tracking || current.target_site != site as u8 {
                return false;
            }
            current.site_calls = current.site_calls.saturating_add(1);
            current.active_site = site as u8;
            current.active_occurrence = current.site_calls;
            current.active_layout = expected_layout;
            if current.active_occurrence == current.target_occurrence {
                current.expected_layout = current.active_layout;
            }
            state.set(current);
            true
        })
        .unwrap_or(false);
    let guard = SiteGuard { entered };
    let result = reserve();
    drop(guard);
    result
}

fn should_refuse(layout: Layout) -> bool {
    if ACTIVE_FAILPOINTS.load(Ordering::Relaxed) == 0 {
        return false;
    }
    STATE
        .try_with(|state| {
            let mut current = state.get();
            let requested = (layout.size(), layout.align());
            if !current.tracking
                || !current.armed
                || current.active_site != current.target_site
                || current.active_occurrence != current.target_occurrence
                || current.active_layout != Some(requested)
            {
                return false;
            }
            current.armed = false;
            current.refusal_count = current.refusal_count.saturating_add(1);
            current.refused_site = current.active_site;
            current.refused_occurrence = current.active_occurrence;
            current.requested_layout = Some(requested);
            state.set(current);
            true
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::with_refusal;
    use crate::allocation::{AllocationSite, reserve_exact};
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[test]
    fn refuses_only_the_target_site_once_and_records_its_layout() {
        let (results, observation) = with_refusal(AllocationSite::Pfs0Metadata, 1, || {
            let _unrelated = Vec::<u8>::with_capacity(1);

            let mut other_site = Vec::<u8>::new();
            let other_result = reserve_exact(&mut other_site, 1, AllocationSite::Pfs0Entries);

            let mut target = Vec::<u8>::new();
            let first_result = reserve_exact(&mut target, 3, AllocationSite::Pfs0Metadata);
            let second_result = reserve_exact(&mut target, 3, AllocationSite::Pfs0Metadata);
            (
                other_result.is_ok(),
                first_result.is_err(),
                second_result.is_ok(),
            )
        });

        assert_eq!(results, (true, true, true));
        assert!(
            observation.is_exact_refusal(AllocationSite::Pfs0Metadata, 1),
            "{observation:?}"
        );
        assert_eq!(observation.site_calls, 2);
        assert_eq!(observation.expected_layout, Some((3, 1)));
        assert_eq!(observation.requested_layout, Some((3, 1)));
    }

    #[test]
    fn unobserved_target_stays_armed_until_the_scope_cleans_it_up() {
        let (result, observation) = with_refusal(AllocationSite::Pfs0Metadata, 1, || {
            let unrelated = Vec::<u8>::with_capacity(1);
            unrelated.capacity()
        });

        assert_eq!(result, 1);
        assert!(observation.tracking_started);
        assert_eq!(observation.site_calls, 0);
        assert_eq!(observation.refusal_count, 0);
        assert!(observation.armed_on_finish);
        assert!(!is_tracking());
    }

    #[test]
    fn refusal_state_is_isolated_between_threads() {
        let (result, observation) = with_refusal(AllocationSite::Pfs0Metadata, 1, || {
            let other_thread = std::thread::spawn(|| {
                let mut values = Vec::<u8>::new();
                reserve_exact(&mut values, 1, AllocationSite::Pfs0Metadata).is_ok()
            });
            let other_thread_result = other_thread.join().expect("worker thread completes");

            let mut values = Vec::<u8>::new();
            let target_result = reserve_exact(&mut values, 1, AllocationSite::Pfs0Metadata);
            (other_thread_result, target_result.is_err())
        });

        assert_eq!(result, (true, true));
        assert!(observation.is_exact_refusal(AllocationSite::Pfs0Metadata, 1));
    }

    #[test]
    fn refusal_scope_disarms_when_the_action_unwinds() {
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _ = with_refusal(AllocationSite::Pfs0Metadata, 1, || panic!("test unwind"));
        }));

        assert!(unwind.is_err());
        assert!(!is_tracking());
    }

    fn is_tracking() -> bool {
        super::STATE
            .try_with(|state| state.get().tracking)
            .unwrap_or(false)
    }
}
