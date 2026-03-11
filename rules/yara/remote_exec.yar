/*
 * YARA Rules for Remote Execution Detection
 * skill-veil: Behavioral & Supply-Chain Security Analysis
 */

rule SkillVeil_CurlPipeBash
{
    meta:
        description = "Detects curl piped to bash shell"
        category = "remote_exec"
        severity = "critical"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $curl_bash1 = /curl\s+[^\|]+\|\s*(ba)?sh/ nocase
        $curl_bash2 = /curl\s+-[sSkLfO]*\s+[^\|]+\|\s*(ba)?sh/ nocase
        $curl_bash3 = "curl -sSL" nocase
        $pipe_sh = "| sh" nocase
        $pipe_bash = "| bash" nocase

    condition:
        any of ($curl_bash*) or (($curl_bash3) and (($pipe_sh) or ($pipe_bash)))
}

rule SkillVeil_WgetPipeBash
{
    meta:
        description = "Detects wget piped to bash shell"
        category = "remote_exec"
        severity = "critical"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $wget_bash1 = /wget\s+[^\|]+\|\s*(ba)?sh/ nocase
        $wget_bash2 = /wget\s+-[qO-]+\s+[^\|]+\|\s*(ba)?sh/ nocase
        $wget_o = "wget -O -" nocase

    condition:
        any of them
}

rule SkillVeil_PowerShellDownloadExecute
{
    meta:
        description = "Detects PowerShell download and execute patterns"
        category = "remote_exec"
        severity = "critical"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $iwr_iex = /Invoke-WebRequest[^\|]+\|\s*iex/ nocase
        $iwr_invoke = /Invoke-WebRequest[^\|]+\|\s*Invoke-Expression/ nocase
        $iex_iwr = /IEX\s*\([^\)]*Invoke-WebRequest/ nocase
        $webclient = "DownloadString" nocase
        $iex = "Invoke-Expression" nocase
        $powershell_enc = /powershell\s+-e(nc)?\s+[A-Za-z0-9+\/=]{20,}/ nocase

    condition:
        any of ($iwr_*) or any of ($iex_*) or (($webclient) and ($iex)) or ($powershell_enc)
}

rule SkillVeil_BashReverseShell
{
    meta:
        description = "Detects bash reverse shell patterns"
        category = "remote_exec"
        severity = "critical"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $bash_tcp = /bash\s+-i\s+>&\s*\/dev\/tcp\// nocase
        $dev_tcp = /\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+/
        $exec_tcp = /exec\s+\d+<>\/dev\/tcp\//

    condition:
        any of them
}

rule SkillVeil_NetcatReverseShell
{
    meta:
        description = "Detects netcat reverse shell patterns"
        category = "remote_exec"
        severity = "critical"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $nc_e = /(nc|ncat|netcat)\s+[^\n]*-e\s+(\/bin\/)?(ba)?sh/ nocase
        $nc_c = /(nc|ncat|netcat)\s+[^\n]*-c\s+(\/bin\/)?(ba)?sh/ nocase
        $nc_ip = /(nc|ncat|netcat)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+/

    condition:
        any of them
}

rule SkillVeil_PythonReverseShell
{
    meta:
        description = "Detects Python reverse shell patterns"
        category = "remote_exec"
        severity = "critical"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $py_socket = "socket.socket" nocase
        $py_connect = ".connect(" nocase
        $py_subprocess = "subprocess" nocase
        $py_pty = "pty.spawn" nocase
        $py_exec = "os.dup2" nocase

    condition:
        ($py_socket and $py_connect) and any of ($py_subprocess, $py_pty, $py_exec)
}

rule SkillVeil_PerlReverseShell
{
    meta:
        description = "Detects Perl reverse shell patterns"
        category = "remote_exec"
        severity = "critical"
        author = "skill-veil"
        date = "2024-01-01"

    strings:
        $perl_socket = /perl\s+-e\s+['"]\s*use\s+Socket/
        $perl_connect = "connect(S" nocase
        $perl_exec = "exec(" nocase

    condition:
        $perl_socket or ($perl_connect and $perl_exec)
}
