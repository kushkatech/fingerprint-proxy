use crate::ja4t::Ja4TInput;
use crate::tcp::os_specific::TcpMetadataSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TcpFallbackPolicy {
    Disabled,
    #[default]
    AllowEmptyOptionKinds,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpFallbackResult {
    Derived(Ja4TInput),
    Unavailable,
}

pub fn derive_from_snapshot(
    snapshot: &TcpMetadataSnapshot,
    policy: TcpFallbackPolicy,
) -> TcpFallbackResult {
    if snapshot.window_size.is_none() {
        return TcpFallbackResult::Unavailable;
    }

    match policy {
        TcpFallbackPolicy::Disabled => TcpFallbackResult::Unavailable,
        TcpFallbackPolicy::AllowEmptyOptionKinds => TcpFallbackResult::Derived(Ja4TInput {
            window_size: snapshot.window_size,
            option_kinds_in_order: snapshot.option_kinds_in_order.clone().unwrap_or_default(),
            mss: snapshot.mss,
            window_scale: snapshot.window_scale,
        }),
    }
}
