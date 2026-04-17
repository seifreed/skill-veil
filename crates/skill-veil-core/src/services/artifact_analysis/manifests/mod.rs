mod build;
mod container;
mod javascript;
mod python;
mod rust_cargo;

pub(crate) use build::{analyze_makefile, makefile_capabilities, makefile_relations};
pub(crate) use container::{
    analyze_docker_compose, analyze_dockerfile, docker_compose_capabilities,
    docker_compose_relations, dockerfile_capabilities, dockerfile_relations,
};
pub(crate) use javascript::{
    analyze_npmrc, analyze_package_json, npmrc_capabilities, npmrc_relations,
    package_json_capabilities, package_json_expected_lockfiles, package_json_relations,
};
pub(crate) use python::{
    analyze_pip_conf, analyze_pyproject_toml, analyze_requirements_txt, pip_conf_capabilities,
    pip_conf_relations, pyproject_expected_lockfiles, pyproject_toml_capabilities,
    requirements_txt_capabilities,
};
pub(crate) use rust_cargo::{analyze_cargo_toml, cargo_toml_capabilities};

use std::path::PathBuf;

pub(super) fn sibling_has_file(sibling_files: &[PathBuf], name: &str) -> bool {
    sibling_files.iter().any(|f| {
        f.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.eq_ignore_ascii_case(name))
    })
}
