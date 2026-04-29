mod classify;
mod model;
mod signals;

pub(crate) use self::classify::contains_internal_network_target;
pub(crate) use self::signals::{
    contains_internal_network_action, contains_ssrf_like_fetch_line,
    looks_like_local_control_plane_reference, looks_like_local_dev_reference,
};
