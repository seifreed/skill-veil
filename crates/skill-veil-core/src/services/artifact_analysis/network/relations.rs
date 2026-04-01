use super::patterns::RE_HTTP_URL;
use super::super::ArtifactLink;
use crate::domain_types::RemoteRelationKind;

const DOWNLOAD_HINTS: &[&str] = &[
    ".tgz",
    ".tar",
    ".tar.gz",
    ".zip",
    ".whl",
    ".crate",
    ".gem",
    ".jar",
    ".exe",
    ".dmg",
    ".msi",
];

impl RemoteRelationKind {
    fn classify(url: &str) -> Self {
        if is_download_like_url(url) {
            Self::Downloads
        } else {
            Self::ConnectsTo
        }
    }
}

fn is_download_like_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    has_download_hint(&lower)
}

pub(crate) fn extract_http_urls(content: &str) -> Vec<String> {
    RE_HTTP_URL
        .find_iter(content)
        .map(|m| trim_trailing_url_delimiters(m.as_str()).to_string())
        .collect()
}

pub(crate) fn generic_url_relations(content: &str) -> Vec<ArtifactLink> {
    extract_http_urls(content)
        .into_iter()
        .map(artifact_link_for_remote_url)
        .collect()
}

pub(crate) fn is_common_lockfile_source(url: &str) -> bool {
    common_lockfile_hosts()
        .iter()
        .any(|host| url.contains(host))
}

fn common_lockfile_hosts() -> &'static [&'static str] {
    &[
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "repo.yarnpkg.com",
        "mirrors.tencentyun.com",
        "registry.npmmirror.com",
        "registry.yarnpkg.cn",
    ]
}

fn trim_trailing_url_delimiters(url: &str) -> &str {
    url.trim_end_matches(&['"', '\'', ')'][..])
}

fn artifact_link_for_remote_url(target: String) -> ArtifactLink {
    ArtifactLink {
        relation: relation_kind_for_url(&target).relation(),
        target,
    }
}

fn relation_kind_for_url(url: &str) -> RemoteRelationKind {
    RemoteRelationKind::classify(url)
}

fn has_download_hint(lower_url: &str) -> bool {
    download_suffix_matched(lower_url) || download_path_hint_matched(lower_url)
}

fn download_suffix_matched(lower_url: &str) -> bool {
    DOWNLOAD_HINTS.iter().any(|suffix| lower_url.contains(suffix))
}

fn download_path_hint_matched(lower_url: &str) -> bool {
    lower_url.contains("/download")
        || lower_url.contains("/releases/")
        || lower_url.contains("/archive/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact_graph::ArtifactRelation;

    #[test]
    fn generic_relations_classify_download_artifacts() {
        let links = generic_url_relations("curl https://example.com/pkg-1.0.0.tgz");
        assert!(matches!(links[0].relation, ArtifactRelation::Downloads));
    }

    #[test]
    fn generic_relations_classify_service_endpoints_as_connections() {
        let links = generic_url_relations("fetch('https://api.example.com/v1/status')");
        assert!(matches!(links[0].relation, ArtifactRelation::ConnectsTo));
    }

    #[test]
    fn common_lockfile_sources_are_recognized() {
        assert!(is_common_lockfile_source("https://registry.npmjs.org/lodash/-/lodash.tgz"));
        assert!(!is_common_lockfile_source("https://downloads.example.com/app.zip"));
    }

    #[test]
    fn trailing_quotes_are_trimmed_from_extracted_urls() {
        let urls = extract_http_urls(r#"source "https://registry.npmjs.org/pkg.tgz""#);
        assert_eq!(urls, vec!["https://registry.npmjs.org/pkg.tgz"]);
    }

    #[test]
    fn url_delimiter_trimmer_handles_quotes_and_parentheses() {
        assert_eq!(
            trim_trailing_url_delimiters("https://example.com/tool.zip\")"),
            "https://example.com/tool.zip"
        );
    }

    #[test]
    fn download_like_classifier_catches_release_archives() {
        assert!(is_download_like_url("https://github.com/acme/tool/releases/download/v1.0.0/tool.zip"));
        assert!(!is_download_like_url("https://api.example.com/v1/jobs"));
    }

    #[test]
    fn multiple_urls_preserve_mixed_relation_kinds() {
        let links = generic_url_relations(
            "fetch https://api.example.com/v1/status && curl https://example.com/tool.tar.gz",
        );
        assert_eq!(links.len(), 2);
        assert!(matches!(links[0].relation, ArtifactRelation::ConnectsTo));
        assert!(matches!(links[1].relation, ArtifactRelation::Downloads));
    }

    #[test]
    fn download_classifier_catches_explicit_download_paths_without_extensions() {
        assert!(is_download_like_url("https://example.com/download?id=tool"));
        assert!(!is_download_like_url("https://example.com/api/status"));
    }

    #[test]
    fn extracted_urls_trim_trailing_parenthesis_and_quote_in_mixed_content() {
        let urls = extract_http_urls(r#"curl (https://example.com/tool.tar.gz')"#);
        assert_eq!(urls, vec!["https://example.com/tool.tar.gz"]);
    }

    #[test]
    fn registry_tarballs_are_classified_as_downloads_even_for_lockfile_hosts() {
        let links = generic_url_relations("https://registry.npmjs.org/demo/-/demo-1.0.0.tgz");
        assert!(matches!(links[0].relation, ArtifactRelation::Downloads));
    }

    #[test]
    fn release_and_archive_hints_are_treated_as_download_paths() {
        assert!(download_path_hint_matched(
            "https://example.com/releases/download/v1/app"
        ));
        assert!(download_path_hint_matched(
            "https://example.com/archive/latest"
        ));
        assert!(!download_path_hint_matched("https://example.com/api/status"));
    }

    #[test]
    fn known_binary_suffixes_are_treated_as_downloads() {
        assert!(download_suffix_matched("https://example.com/tool.whl"));
        assert!(download_suffix_matched("https://example.com/tool.exe"));
        assert!(!download_suffix_matched("https://example.com/status.json"));
    }

    #[test]
    fn artifact_link_builder_preserves_target_and_relation() {
        let link = artifact_link_for_remote_url("https://example.com/tool.zip".to_string());
        assert_eq!(link.target, "https://example.com/tool.zip");
        assert!(matches!(link.relation, ArtifactRelation::Downloads));
    }

    #[test]
    fn relation_kind_classifier_distinguishes_downloads_from_service_endpoints() {
        assert!(matches!(
            relation_kind_for_url("https://example.com/tool.tar.gz"),
            RemoteRelationKind::Downloads
        ));
        assert!(matches!(
            relation_kind_for_url("https://api.example.com/v1/status"),
            RemoteRelationKind::ConnectsTo
        ));
    }

    #[test]
    fn registry_service_endpoint_without_archive_hint_stays_connects_to() {
        assert!(matches!(
            relation_kind_for_url("https://registry.npmjs.org/-/v1/search?text=demo"),
            RemoteRelationKind::ConnectsTo
        ));
    }

    #[test]
    fn common_lockfile_hosts_stay_registry_scoped() {
        assert!(common_lockfile_hosts().contains(&"registry.npmjs.org"));
        assert!(!common_lockfile_hosts().contains(&"api.example.com"));
    }

    #[test]
    fn registry_download_tarball_stays_download_even_on_known_registry_host() {
        let relation = relation_kind_for_url("https://registry.yarnpkg.com/demo/-/demo-1.0.0.tgz");
        assert!(matches!(relation, RemoteRelationKind::Downloads));
    }

    #[test]
    fn download_hint_helper_joins_suffix_and_path_heuristics() {
        assert!(has_download_hint("https://example.com/tool.zip"));
        assert!(has_download_hint("https://example.com/releases/download/v1/tool"));
        assert!(!has_download_hint("https://example.com/api/status"));
    }

    #[test]
    fn extracted_urls_preserve_order_of_occurrence() {
        let urls = extract_http_urls(
            "curl https://api.example.com/status && curl https://example.com/tool.zip",
        );
        assert_eq!(
            urls,
            vec![
                "https://api.example.com/status".to_string(),
                "https://example.com/tool.zip".to_string()
            ]
        );
    }
}
