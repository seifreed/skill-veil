//! Container manifest dispatch — re-exports the detector entry points
//! from `crate::detectors::manifests::container`.

pub(crate) use crate::detectors::manifests::container::compose::{
    analyze_docker_compose, docker_compose_capabilities, docker_compose_relations,
};
pub(crate) use crate::detectors::manifests::container::dockerfile::{
    analyze_dockerfile, dockerfile_capabilities, dockerfile_relations,
};
