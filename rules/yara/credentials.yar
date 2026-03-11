/*
 * YARA Rules for Credential and Secret Detection
 * skill-veil: Behavioral & Supply-Chain Security Analysis
 */

rule SkillVeil_AWSCredentials
{
    meta:
        description = "Detects AWS access keys and secrets"
        category = "credential_exposure"
        severity = "critical"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $aws_access_key = /AKIA[0-9A-Z]{16}/
        $aws_secret = /aws_secret_access_key\s*[=:]\s*[A-Za-z0-9\/+=]{40}/ nocase
        $aws_session = /aws_session_token\s*[=:]/ nocase

    condition:
        any of them
}

rule SkillVeil_GitHubTokens
{
    meta:
        description = "Detects GitHub personal access tokens"
        category = "credential_exposure"
        severity = "critical"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $ghp = /ghp_[A-Za-z0-9]{36}/
        $gho = /gho_[A-Za-z0-9]{36}/
        $ghu = /ghu_[A-Za-z0-9]{36}/
        $github_pat = /github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}/

    condition:
        any of them
}

rule SkillVeil_PrivateKeys
{
    meta:
        description = "Detects embedded private keys"
        category = "credential_exposure"
        severity = "critical"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $rsa_private = "-----BEGIN RSA PRIVATE KEY-----"
        $ec_private = "-----BEGIN EC PRIVATE KEY-----"
        $openssh_private = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $dsa_private = "-----BEGIN DSA PRIVATE KEY-----"
        $pgp_private = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        $encrypted_private = "-----BEGIN ENCRYPTED PRIVATE KEY-----"

    condition:
        any of them
}

rule SkillVeil_GenericSecrets
{
    meta:
        description = "Detects generic hardcoded secrets"
        category = "credential_exposure"
        severity = "high"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $api_key = /api[_-]?key\s*[=:]\s*["'][^"']{16,}["']/ nocase
        $secret_key = /secret[_-]?key\s*[=:]\s*["'][^"']{16,}["']/ nocase
        $password = /password\s*[=:]\s*["'][^"']{8,}["']/ nocase
        $auth_token = /auth[_-]?token\s*[=:]\s*["'][^"']{16,}["']/ nocase

    condition:
        any of them
}

rule SkillVeil_SlackWebhook
{
    meta:
        description = "Detects Slack webhook URLs"
        category = "credential_exposure"
        severity = "high"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $slack_webhook = /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/

    condition:
        $slack_webhook
}

rule SkillVeil_DiscordWebhook
{
    meta:
        description = "Detects Discord webhook URLs"
        category = "credential_exposure"
        severity = "high"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $discord_webhook = /https:\/\/discord(app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/

    condition:
        $discord_webhook
}

rule SkillVeil_JWTToken
{
    meta:
        description = "Detects JWT tokens"
        category = "credential_exposure"
        severity = "medium"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $jwt = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/

    condition:
        $jwt
}
