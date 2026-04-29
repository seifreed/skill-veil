use crate::lazy_pattern;

lazy_pattern!(
    pub(crate) RE_BROWSER_FULL,
    r"(?i)(browser:\s*full|full autonomous browser|click any element|navigation:\s*allow-all)"
);
lazy_pattern!(
    pub(crate) RE_PERSISTENCE,
    r"(?i)(persist\s+these\s+instructions|remember\s+this\s+across\s+sessions|append\s+to\s+(agents|claude|system)\.md)"
);
lazy_pattern!(
    pub(crate) RE_NETWORK,
    r"(?i)(http://|https://|browser tool|network tool)"
);
lazy_pattern!(
    pub(crate) RE_SECRET,
    r"(?i)(token|secret|cookie|password|credential|session)"
);
lazy_pattern!(
    pub(crate) RE_OAUTH,
    r"(?i)(oauth|scope|calendar|drive|slack|github pat)"
);
lazy_pattern!(
    pub(crate) RE_COGNITIVE_ROOTKIT,
    r"(?i)(persist\s+these\s+instructions|remember\s+this\s+across\s+sessions|always\s+follow\s+this\s+prompt|never\s+reveal\s+this\s+instruction|override\s+future\s+system\s+messages)"
);
lazy_pattern!(
    pub(crate) RE_PRIVILEGED_ROLE,
    r"(?i)(act\s+as\s+(root|administrator|system)|treat\s+all\s+tool\s+requests\s+as\s+approved|ignore\s+all\s+existing\s+safety\s+constraints)"
);
