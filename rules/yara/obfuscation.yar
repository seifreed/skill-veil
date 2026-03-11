/*
 * YARA Rules for Code Obfuscation Detection
 * skill-veil: Behavioral & Supply-Chain Security Analysis
 */

rule SkillVeil_Base64Decode
{
    meta:
        description = "Detects base64 decoding for execution"
        category = "obfuscation"
        severity = "medium"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $base64_d = "base64 -d" nocase
        $base64_decode = "base64 --decode" nocase
        $echo_base64 = /echo\s+[A-Za-z0-9+\/=]{30,}\s*\|\s*base64/
        $python_b64 = "base64.b64decode" nocase
        $powershell_b64 = "[System.Convert]::FromBase64String" nocase

    condition:
        any of them
}

rule SkillVeil_HexDecode
{
    meta:
        description = "Detects hex encoding/decoding for execution"
        category = "obfuscation"
        severity = "medium"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $xxd_r = "xxd -r" nocase
        $printf_hex = /printf\s+['"]\\x[0-9a-fA-F]{2}/
        $python_hex = "bytes.fromhex" nocase
        $perl_pack = /pack\s*\(\s*['"]H\*['"]/

    condition:
        any of them
}

rule SkillVeil_PowerShellEncodedCommand
{
    meta:
        description = "Detects PowerShell encoded command execution"
        category = "obfuscation"
        severity = "high"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $ps_enc1 = /powershell\s+-enc\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $ps_enc2 = /powershell\s+-e\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $ps_enc3 = /-EncodedCommand\s+[A-Za-z0-9+\/=]{20,}/ nocase
        $ps_enc4 = /-ec\s+[A-Za-z0-9+\/=]{20,}/ nocase

    condition:
        any of them
}

rule SkillVeil_EvalExec
{
    meta:
        description = "Detects dynamic code evaluation"
        category = "obfuscation"
        severity = "medium"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $eval_js = /eval\s*\([^)]+\)/ nocase
        $eval_py = /exec\s*\([^)]+\)/ nocase
        $eval_php = /eval\s*\([^)]+\)/ nocase
        $invoke_expr = "Invoke-Expression" nocase
        $iex = /\biex\b/ nocase

    condition:
        any of them
}

rule SkillVeil_CharCodeObfuscation
{
    meta:
        description = "Detects character code obfuscation"
        category = "obfuscation"
        severity = "medium"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $char_ps = /\[char\]\s*\d+.*\[char\]\s*\d+/
        $chr_py = /chr\(\d+\).*chr\(\d+\)/
        $fromcharcode = "String.fromCharCode" nocase
        $chr_php = /chr\s*\(\s*\d+\s*\)/

    condition:
        any of them
}

rule SkillVeil_GzipCompression
{
    meta:
        description = "Detects gzip compressed payloads"
        category = "obfuscation"
        severity = "low"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $gzip_d = "gzip -d" nocase
        $gunzip = "gunzip" nocase
        $zcat = "zcat" nocase
        $python_gzip = "gzip.decompress" nocase
        $io_compression = "IO.Compression.GZipStream" nocase

    condition:
        any of them
}

rule SkillVeil_StringReversal
{
    meta:
        description = "Detects string reversal obfuscation"
        category = "obfuscation"
        severity = "low"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $rev_bash = "| rev" nocase
        $reverse_py = "[::-1]"
        $reverse_ps = "[array]::Reverse" nocase

    condition:
        any of them
}
