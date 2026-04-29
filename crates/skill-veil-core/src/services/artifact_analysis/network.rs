//! Network-related orchestration: URL extraction and lockfile-source
//! recognition. Domain-rule logic for target classification and webhook
//! exposure lives in the sibling `targets` and `webhook` submodules,
//! which are in the process of being relocated under `crate::detectors`.

pub(crate) mod patterns;

use patterns::RE_HTTP_URL;

pub(super) fn extract_http_urls(content: &str) -> Vec<String> {
    RE_HTTP_URL
        .find_matches(content)
        .into_iter()
        .map(|m| {
            m.matched_text
                .trim_end_matches(&['"', '\'', ')'][..])
                .to_string()
        })
        .collect()
}

pub(super) fn is_common_lockfile_source(url: &str) -> bool {
    [
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "repo.yarnpkg.com",
        "mirrors.tencentyun.com",
        "registry.npmmirror.com",
        "registry.yarnpkg.cn",
    ]
    .iter()
    .any(|host| url.contains(host))
}
