//! Fallible reservation helpers for bounded parser allocations.

use std::collections::TryReserveError;

/// Identifies a bounded reservation that unit tests can refuse directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
#[allow(dead_code)] // The standalone binary shares this file but uses only key-file reservations.
pub(crate) enum AllocationSite {
    KeyFileBytes,
    Pfs0Metadata,
    Pfs0Entries,
    Pfs0Spans,
    Pfs0NameBytes,
    NspRecords,
    NspMembers,
    NspSpans,
    NspSourceHashBuffer,
    NspSectionHashBuffer,
    NcaHeaderSpans,
    NcaHeaderPartitions,
}

/// Reserves additional vector capacity and retains the reservation's test site.
pub(crate) fn reserve_exact<T>(
    values: &mut Vec<T>,
    additional: usize,
    site: AllocationSite,
) -> Result<(), TryReserveError> {
    #[cfg(test)]
    {
        let layout = values
            .len()
            .checked_add(additional)
            .and_then(|capacity| std::alloc::Layout::array::<T>(capacity).ok());
        crate::test_allocator::reserve_with_layout(site, layout, || {
            values.try_reserve_exact(additional)
        })
    }

    #[cfg(not(test))]
    {
        let _ = site;
        values.try_reserve_exact(additional)
    }
}

/// Reserves additional string capacity and retains the reservation's test site.
#[allow(dead_code)] // The standalone binary does not include the PFS0 parser.
pub(crate) fn reserve_string_exact(
    value: &mut String,
    additional: usize,
    site: AllocationSite,
) -> Result<(), TryReserveError> {
    #[cfg(test)]
    {
        let layout = value
            .len()
            .checked_add(additional)
            .and_then(|capacity| std::alloc::Layout::array::<u8>(capacity).ok());
        crate::test_allocator::reserve_with_layout(site, layout, || {
            value.try_reserve_exact(additional)
        })
    }

    #[cfg(not(test))]
    {
        let _ = site;
        value.try_reserve_exact(additional)
    }
}
