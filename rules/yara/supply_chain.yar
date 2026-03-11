/*
 * YARA Rules for Supply Chain Security Detection
 * skill-veil: Behavioral & Supply-Chain Security Analysis
 */

rule SkillVeil_ChmodAndExecute
{
    meta:
        description = "Detects chmod +x followed by immediate execution"
        category = "supply_chain"
        severity = "high"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $chmod_exec = /chmod\s+\+x\s+[^\n]+&&\s*\.\/[^\s]+/
        $chmod_run = /chmod\s+\+x\s+[^\s]+\s*;\s*\.\/[^\s]+/
        $chmod_777 = "chmod 777" nocase

    condition:
        any of them
}

rule SkillVeil_DockerPrivileged
{
    meta:
        description = "Detects privileged Docker container patterns"
        category = "supply_chain"
        severity = "critical"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $privileged = "--privileged" nocase
        $host_mount = "-v /:/host" nocase
        $docker_sock = "docker.sock" nocase
        $cap_all = "--cap-add=ALL" nocase

    condition:
        any of them
}

rule SkillVeil_UntrustedRepository
{
    meta:
        description = "Detects addition of untrusted repositories"
        category = "supply_chain"
        severity = "high"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $add_repo = "add-apt-repository" nocase
        $ppa = "ppa:" nocase
        $sources_list = "/etc/apt/sources.list"
        $apt_key = "apt-key add" nocase
        $gpg_import = "gpg --import" nocase

    condition:
        any of them
}

rule SkillVeil_NPMGlobalInstall
{
    meta:
        description = "Detects global npm package installation without version pinning"
        category = "supply_chain"
        severity = "medium"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $npm_g = /npm\s+install\s+-g\s+[^@\s]+\s/
        $npm_global = /npm\s+install\s+--global\s+[^@\s]+\s/

    condition:
        any of them
}

rule SkillVeil_PipNoVersion
{
    meta:
        description = "Detects pip package installation without version pinning"
        category = "supply_chain"
        severity = "medium"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $pip_install = /pip3?\s+install\s+[a-zA-Z][a-zA-Z0-9_-]+\s/
        $pip_no_version = /pip3?\s+install\s+(?!.*[=<>])[a-zA-Z]/

    condition:
        any of them
}

rule SkillVeil_DockerLatestTag
{
    meta:
        description = "Detects Docker images with :latest or no tag"
        category = "supply_chain"
        severity = "medium"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $docker_latest = /:latest\s/
        $from_latest = /FROM\s+[^:]+:latest/
        $pull_no_tag = /docker\s+pull\s+[^:\s]+\s/

    condition:
        any of them
}

rule SkillVeil_BinaryDownload
{
    meta:
        description = "Detects downloading of binary files"
        category = "supply_chain"
        severity = "high"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $curl_exe = /curl\s+[^\s]+\.exe\b/ nocase
        $curl_bin = /curl\s+[^\s]+\.bin\b/ nocase
        $wget_exe = /wget\s+[^\s]+\.exe\b/ nocase
        $wget_bin = /wget\s+[^\s]+\.bin\b/ nocase
        $download_msi = /\.(msi|dmg|pkg|deb|rpm)\b/ nocase

    condition:
        any of them
}
