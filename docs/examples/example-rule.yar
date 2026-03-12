rule ExampleRemoteExecSignature {
  meta:
    severity = "high"
    category = "remote_exec"
    description = "Example signature for fetch-and-exec bootstrap patterns"

  strings:
    $curl = /curl\s+-fsSL/i
    $bash = /\|\s*bash/i

  condition:
    $curl and $bash
}
