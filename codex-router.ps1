$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Target = if ($env:MODEL_ROUTER_TARGET) { $env:MODEL_ROUTER_TARGET } else { "codex" }
if ($Target -ne "codex") {
  throw "MODEL_ROUTER_TARGET must be codex."
}
$Command = if ($args.Count) { [string]$args[0] } else { "status" }
# The @() wraps the whole `if`, not its branches. PowerShell enumerates a
# statement's output into an assignment, so a one-element array collapses to
# the element itself: `tray status` bound $Arguments to the String "status",
# and $Arguments[0] then indexed the string and yielded "s". Every
# single-argument subcommand -- tray status/start/stop/restart/uninstall --
# failed with "Unknown tray action 's'".
$Arguments = @(if ($args.Count -gt 1) { $args[1..($args.Count - 1)] })
$Commands = @(
  "setup", "install", "doctor", "status", "providers", "provider-key", "enable",
  "disable", "chatgpt-session", "uninstall", "update", "rollback", "support-bundle",
  "smoke-test", "start", "stop", "test-model", "discover-models", "local-mlx",
  "signed-routing", "refresh-catalog", "media", "tray", "panel", "companion"
)
if ($Command -notin $Commands) {
  throw "Unknown command '$Command'. Choose: $($Commands -join ', ')."
}
function Invoke-RouterNode([string]$Script, [string[]]$ScriptArguments = @()) {
  & node (Join-Path $Root $Script) @ScriptArguments
  if ($LASTEXITCODE -ne 0) {
    throw "$Script exited with status $LASTEXITCODE."
  }
}

function Resolve-AccountSid([string]$Identity) {
  try {
    return ([Security.Principal.SecurityIdentifier]::new($Identity)).Value
  } catch {
    return ([Security.Principal.NTAccount]::new($Identity)).Translate(
      [Security.Principal.SecurityIdentifier]
    ).Value
  }
}

function Get-ValidatedTrayTask {
  $TaskName = "Codex Router Tray"
  $Task = Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop
  $CurrentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  $PrincipalSid = Resolve-AccountSid ([string]$Task.Principal.UserId)
  if ($PrincipalSid -ne $CurrentSid) {
    throw "Refusing to repair '$TaskName': its principal is not the current user."
  }
  if ($Task.Principal.LogonType.ToString() -ne "Interactive") {
    throw "Refusing to repair '$TaskName': it is not an interactive user task."
  }

  $Actions = @($Task.Actions)
  if ($Actions.Count -ne 1) {
    throw "Refusing to repair '$TaskName': it does not have one recognized action."
  }
  $TaskAction = $Actions[0]
  $Execute = [IO.Path]::GetFullPath(
    [Environment]::ExpandEnvironmentVariables([string]$TaskAction.Execute)
  )
  $Argument = [string]$TaskAction.Arguments

  # A task registered by an installed copy (%LOCALAPPDATA%\codex-router) points
  # at that root, while `tray repair` is often run from a developer checkout's
  # $PSScriptRoot. Requiring the action to equal *this* checkout would reject
  # exactly the person reaching for repair. So the action is recognized by the
  # *shape* of a real companion -- the Tauri release binary, or the Electron
  # runtime plus its app directory -- rather than by which root registered it.
  # The principal/interactive/single-action checks above still stop repair of an
  # arbitrary scheduled task.
  $TauriAction = $Execute.EndsWith(
    "apps\desktop\src-tauri\target\release\codex-router-desktop.exe",
    [StringComparison]::OrdinalIgnoreCase
  ) -and [string]::IsNullOrWhiteSpace($Argument)
  $ElectronAction = $Execute.EndsWith(
    "apps\electron\node_modules\electron\dist\electron.exe",
    [StringComparison]::OrdinalIgnoreCase
  ) -and (
    $Argument.Trim().Trim('"').EndsWith(
      "apps\electron",
      [StringComparison]::OrdinalIgnoreCase
    )
  )
  if (-not ($TauriAction -or $ElectronAction)) {
    throw "Refusing to repair '$TaskName': its action is not a Codex Router tray companion (codex-router-desktop.exe or the Electron app)."
  }

  return [pscustomobject]@{
    Name = $TaskName
    Sid = $CurrentSid
    Execute = [string]$TaskAction.Execute
    Argument = $Argument
  }
}

function Test-TrayTaskFullControl([string]$TaskName, [string]$SidValue) {
  try {
    $Service = New-Object -ComObject "Schedule.Service"
    $Service.Connect()
    $Registered = $Service.GetFolder("\").GetTask($TaskName)
    $Descriptor = [Security.AccessControl.RawSecurityDescriptor]::new(
      $Registered.GetSecurityDescriptor(7)
    )
    foreach ($Ace in $Descriptor.DiscretionaryAcl) {
      if ($Ace -is [Security.AccessControl.CommonAce] -and
          $Ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
          $Ace.SecurityIdentifier.Value -eq $SidValue -and
          ($Ace.AccessMask -band 0x1f01ff) -eq 0x1f01ff) {
        return $true
      }
    }
  } catch {
    # A descriptor we cannot inspect is exactly the case the elevated repair
    # is allowed to address after validating the task's principal and action.
  }
  return $false
}

function Repair-TrayTaskPermissions {
  $Validated = Get-ValidatedTrayTask
  if (Test-TrayTaskFullControl $Validated.Name $Validated.Sid) {
    Write-Output "Tray task permissions are already repairable by the current user."
    return
  }

  # The validated values are the only data the elevated side needs, but they
  # cannot cross the UAC boundary: Start-Process -Verb RunAs goes through
  # ShellExecuteEx -> AppInfo -> CreateProcessAsUser, which rebuilds the child
  # environment from the elevated token, so `$env:CODEX_ROUTER_TRAY_REPAIR_*`
  # would be empty inside the elevated process. Instead the four values are
  # embedded as literals in the -EncodedCommand payload, and the elevated side
  # re-reads the task and compares its principal and action against them --
  # the same TOCTOU closure as before, with no process-environment handoff.
  foreach ($Field in "Name", "Sid", "Execute", "Argument") {
    if ([string]::IsNullOrWhiteSpace([string]$Validated.$Field)) {
      throw "Refusing to repair the tray task: validated $Field is empty."
    }
  }
  $ElevatedScript = @'
$ErrorActionPreference = "Stop"
function Resolve-RepairSid([string]$Identity) {
  try { return ([Security.Principal.SecurityIdentifier]::new($Identity)).Value }
  catch { return ([Security.Principal.NTAccount]::new($Identity)).Translate([Security.Principal.SecurityIdentifier]).Value }
}
$scheduled = Get-ScheduledTask -TaskName __TRAY_TASK__ -ErrorAction Stop
$actions = @($scheduled.Actions)
if ($actions.Count -ne 1) { throw "Tray task action changed before repair." }
$principalSid = Resolve-RepairSid ([string]$scheduled.Principal.UserId)
if ($principalSid -ne __TRAY_SID__ -or
    -not [string]::Equals([string]$actions[0].Execute, __TRAY_EXECUTE__, [StringComparison]::OrdinalIgnoreCase) -or
    -not [string]::Equals([string]$actions[0].Arguments, __TRAY_ARGUMENT__, [StringComparison]::Ordinal)) {
  throw "Tray task identity changed before repair."
}
$service = New-Object -ComObject "Schedule.Service"
$service.Connect()
$registered = $service.GetFolder("\").GetTask(__TRAY_TASK__)
$descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($registered.GetSecurityDescriptor(7))
$sid = [Security.Principal.SecurityIdentifier]::new(__TRAY_SID__)
$fullControl = 0x1f01ff
$hasFullControl = $false
foreach ($ace in $descriptor.DiscretionaryAcl) {
  if ($ace -is [Security.AccessControl.CommonAce] -and
      $ace.AceQualifier -eq [Security.AccessControl.AceQualifier]::AccessAllowed -and
      $ace.SecurityIdentifier.Value -eq $sid.Value -and
      ($ace.AccessMask -band $fullControl) -eq $fullControl) {
    $hasFullControl = $true
    break
  }
}
if (-not $hasFullControl) {
  $newAce = [Security.AccessControl.CommonAce]::new(
    [Security.AccessControl.AceFlags]::None,
    [Security.AccessControl.AceQualifier]::AccessAllowed,
    $fullControl,
    $sid,
    $false,
    $null
  )
  $descriptor.DiscretionaryAcl.InsertAce($descriptor.DiscretionaryAcl.Count, $newAce)
  $sections = [Security.AccessControl.AccessControlSections]::Owner -bor
    [Security.AccessControl.AccessControlSections]::Group -bor
    [Security.AccessControl.AccessControlSections]::Access
  $registered.SetSecurityDescriptor($descriptor.GetSddlForm($sections), 0x10)
}
'@
  # `Replace` substitutes only after the single-quoted here-string is
  # assembled, so the embedded script's own `$...` stays verbatim; each value
  # is wrapped in single quotes (doubling any embedded quote) so it becomes a
  # string literal in the payload, never executable text.
  function ConvertTo-RepairLiteral([string]$Value) {
    return "'" + $Value.Replace("'", "''") + "'"
  }
  $ElevatedScript = $ElevatedScript.Replace(
    "__TRAY_TASK__", (ConvertTo-RepairLiteral ([string]$Validated.Name)))
  $ElevatedScript = $ElevatedScript.Replace(
    "__TRAY_SID__", (ConvertTo-RepairLiteral ([string]$Validated.Sid)))
  $ElevatedScript = $ElevatedScript.Replace(
    "__TRAY_EXECUTE__", (ConvertTo-RepairLiteral ([string]$Validated.Execute)))
  $ElevatedScript = $ElevatedScript.Replace(
    "__TRAY_ARGUMENT__", (ConvertTo-RepairLiteral ([string]$Validated.Argument)))

  # Name the host absolutely because -Verb RunAs forces ShellExecuteEx, whose
  # search order includes the current working directory and every PATH entry;
  # an unelevated attacker who can drop a powershell.exe there would otherwise
  # get it launched behind the UAC prompt, fully elevated. Pin the working
  # directory to SystemRoot so the elevated child runs from a directory no
  # attacker can write.
  $ElevatedPowerShell = Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\powershell.exe"
  if (-not (Test-Path -LiteralPath $ElevatedPowerShell -PathType Leaf)) {
    throw "Cannot locate the elevated PowerShell host at $ElevatedPowerShell."
  }
  $Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($ElevatedScript))
  $Process = Start-Process -FilePath $ElevatedPowerShell -Verb RunAs -Wait -PassThru -WindowStyle Hidden -WorkingDirectory $env:SystemRoot -ArgumentList @(
    "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", $Encoded
  )
  if ($Process.ExitCode -ne 0) {
    throw "Elevated tray permission repair failed with exit code $($Process.ExitCode)."
  }
  if (-not (Test-TrayTaskFullControl $Validated.Name $Validated.Sid)) {
    throw "Task Scheduler still denies the current user control of the tray task."
  }
  Write-Output "Tray task permissions repaired; reinstalling the companion."
}

switch ($Command) {
  "setup" {
    Invoke-RouterNode "src\setup.mjs" $Arguments
  }
  "doctor" {
    Invoke-RouterNode "src\doctor.mjs" $Arguments
  }
  "status" {
    Invoke-RouterNode "src\doctor.mjs" $Arguments
  }
  "providers" { Invoke-RouterNode "src\providers.mjs" $Arguments }
  "provider-key" { Invoke-RouterNode "src\provider-key.mjs" $Arguments }
  "chatgpt-session" { Invoke-RouterNode "src\chatgpt-session.mjs" $Arguments }
  # `bin/install` accepts --prepare-only/--migrate-known/--force-deps, so the
  # Windows wrapper has to pass the equivalent switches through instead of
  # dropping them; `./model-router.ps1 codex install -ForceDeps` was silently
  # running a plain install.
  "install" { & (Join-Path $Root "install.ps1") -CheckoutInstall -Target $Target @Arguments }
  "enable" { & (Join-Path $Root "install.ps1") -CheckoutInstall -Target $Target @Arguments }
  "disable" {
    Invoke-RouterNode "src\config-manager.mjs" @("disable")
    Invoke-RouterNode "src\service.mjs" @("uninstall")
  }
  "uninstall" {
    Invoke-RouterNode "src\config-manager.mjs" @("disable")
    Invoke-RouterNode "src\service.mjs" @("uninstall")
  }
  "update" {
    # `update check` stays a read-only comparison; a bare `update` installs.
    $UpdateArguments = if ($Arguments.Count) { $Arguments } else { @("update") }
    Invoke-RouterNode "src\update.mjs" $UpdateArguments
  }
  "rollback" {
    # The subcommand is fixed, so the caller's flags are appended to it rather
    # than replacing it -- the shape `bin/rollback` uses (`update.mjs rollback
    # "$@"`). Hardcoding the list here made `rollback --force` unreachable on
    # Windows, which is the only way past tracked edits that block a rollback.
    Invoke-RouterNode "src\update.mjs" (@("rollback") + $Arguments)
  }
  "signed-routing" {
    Invoke-RouterNode "src\control.mjs" (@("signed-routing") + $Arguments)
  }
  "refresh-catalog" { Invoke-RouterNode "src\refresh-catalog.mjs" $Arguments }
  "support-bundle" { Invoke-RouterNode "src\support-bundle.mjs" $Arguments }
  "smoke-test" {
    Invoke-RouterNode "src\smoke-test.mjs" $Arguments
  }
  "start" { Invoke-RouterNode "src\start.mjs" $Arguments }
  "stop" { Invoke-RouterNode "src\service.mjs" @("stop") }
  "test-model" { Invoke-RouterNode "src\compatibility-test.mjs" $Arguments }
  "discover-models" { Invoke-RouterNode "src\model-discovery.mjs" $Arguments }
  "local-mlx" { Invoke-RouterNode "src\local-mlx.mjs" $Arguments }
  "media" { Invoke-RouterNode "src\minimax-media.mjs" $Arguments }
  # The companion with nothing to build and nothing to download. The router is
  # already serving it; this is the one thing that knows the address.
  "panel" { Invoke-RouterNode "src\panel.mjs" $Arguments }
  # The Windows counterpart of ./bin/model-router-tray. Before this, macOS and
  # Linux had one command that built and supervised the companion and Windows
  # had none -- bin/model-router-tray only told you to go read a build script.
  # Build when the sources moved, then hand it to Task Scheduler, which starts
  # it now and again at every logon.
  "tray" {
    $Action = if ($Arguments.Count) { [string]$Arguments[0] } else { "install" }
    if ($Action -notin @("install", "status", "start", "stop", "restart", "uninstall", "rebuild", "repair")) {
      throw "Unknown tray action '$Action'. Choose: install, status, start, stop, restart, uninstall, rebuild, repair."
    }
    if ($Action -eq "repair") {
      Write-Output "Repairing the tray task's permissions. If repair is needed, the companion will then be rebuilt or reinstalled (a small step), re-registered, and started by Task Scheduler at every logon."
      Repair-TrayTaskPermissions
      $Action = "install"
    }
    # `rebuild` is `control tray rebuild`'s Windows half: build unconditionally
    # -- bypassing the source-fingerprint skip that `install` uses -- then
    # restart whichever companion Task Scheduler already supervises.
    if ($Action -eq "rebuild") {
      # A running companion keeps its Tauri or Electron binary open, and
      # Windows refuses to overwrite a file another process holds. Building in
      # place over a live tray fails every time, leaving the old companion in
      # place (or broken). So a rebuild stops the supervised task before it
      # builds, and restores the previous instance best-effort if the build or
      # install afterwards fails.
      $TrayWasRunning = $false
      try {
        $TrayState = (& node (Join-Path $Root "src\tray-service.mjs") status | Out-String)
        if ($LASTEXITCODE -eq 0) {
          $TrayWasRunning = ($TrayState | ConvertFrom-Json).loaded -eq $true
        }
      } catch {
        # An unreadable status is not a reason to build over a running tray;
        # stopping first is safe either way, so just record nothing.
        $TrayWasRunning = $false
      }
      try {
        # `stop` is a no-op for an absent or idle task. Only a scheduler
        # failure it cannot classify aborts the rebuild.
        Invoke-RouterNode "src\tray-service.mjs" @("stop")
      } catch {
        if ($TrayWasRunning) { throw }
      }
      try {
        if (Get-Command cargo -ErrorAction SilentlyContinue) {
          & (Join-Path $Root "scripts\build-desktop-tray.ps1") -BinaryOnly
          if ($LASTEXITCODE -ne 0) { throw "Desktop companion build failed." }
          & node (Join-Path $Root "src\install-plan.mjs") record-tray | Out-Null
          if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not stamp the companion build; the next update will rebuild it."
          }
          Invoke-RouterNode "src\tray-service.mjs" @("install")
        } else {
          Write-Output "Cargo is not on PATH; rebuilding the Electron companion instead."
          & (Join-Path $Root "scripts\build-electron-companion.ps1") | Out-Null
          if ($LASTEXITCODE -ne 0) { throw "Electron companion build failed." }
          Invoke-RouterNode "src\tray-service.mjs" @("install-electron")
        }
      } catch {
        if ($TrayWasRunning) {
          # The tray this rebuild replaced is gone or half-replaced and STOPPED.
          # Bring the still-on-disk companion back so the machine is not left
          # trayless by a failed update.
          try {
            Invoke-RouterNode "src\tray-service.mjs" @("start")
            Write-Warning "Companion rebuild failed; the previous companion was restarted."
          } catch {
            Write-Warning "Companion rebuild failed and the previous companion could not be restarted: $($_.Exception.Message)"
          }
        }
        throw
      }
      Write-Output "Companion rebuilt, installed, and started."
      exit 0
    }
    # Rust is the only prerequisite the Tauri shell adds over what the router
    # install already required. Without it this step used to fail and print an
    # apology, which left the machine with no companion at all; the Electron
    # shell renders the same UI and needs only Node.
    if ($Action -eq "install" -and -not (Get-Command cargo -ErrorAction SilentlyContinue)) {
      Write-Output "Cargo is not on PATH, so the Tauri companion cannot be built."
      Write-Output "Building the Electron companion instead; it needs only Node."
      & (Join-Path $Root "scripts\build-electron-companion.ps1") | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Electron companion build failed." }
      Invoke-RouterNode "src\tray-service-windows.mjs" @("install-electron")
      Write-Output "Companion installed and started by Task Scheduler; it returns at every logon."
      Write-Output "Windows 11 hides new tray icons: click the ^ chevron by the clock, then drag the icon onto the taskbar to pin it."
      exit 0
    }
    if ($Action -eq "install") {
      $Plan = & node (Join-Path $Root "src\install-plan.mjs") tray-plan
      if ($LASTEXITCODE -ne 0) { throw "Could not read the tray build plan." }
      if ($Plan.Trim() -eq "skip") {
        Write-Output "Companion already built from these sources; skipping the rebuild."
      } else {
        & (Join-Path $Root "scripts\build-desktop-tray.ps1") -BinaryOnly
        if ($LASTEXITCODE -ne 0) { throw "Desktop companion build failed." }
        # Not silenced: without the stamp every later update rebuilds the
        # companion from scratch, which is the cost this step exists to avoid.
        & node (Join-Path $Root "src\install-plan.mjs") record-tray | Out-Null
        if ($LASTEXITCODE -ne 0) {
          Write-Warning "Could not stamp the companion build; the next update will rebuild it."
        }
      }
    }
    Invoke-RouterNode "src\tray-service.mjs" @($Action)
    if ($Action -eq "install") {
      Write-Output "Tray installed and started by Task Scheduler; it returns at every logon."
      Write-Output "Windows 11 hides new tray icons: click the ^ chevron by the clock, then drag the icon onto the taskbar to pin it."
    }
  }
  # The same companion, built with Node instead of Rust. `tray` needs cargo and
  # several minutes of compiling; this needs what the router install already
  # required, so a machine with no Rust toolchain is not left without one.
  "companion" {
    $Action = if ($Arguments.Count) { [string]$Arguments[0] } else { "install" }
    if ($Action -notin @("install", "status", "start", "stop", "restart", "uninstall")) {
      throw "Unknown companion action '$Action'. Choose: install, status, start, stop, restart, uninstall."
    }
    if ($Action -eq "install") {
      & (Join-Path $Root "scripts\build-electron-companion.ps1") | Out-Null
      if ($LASTEXITCODE -ne 0) { throw "Electron companion build failed." }
      Invoke-RouterNode "src\tray-service-windows.mjs" @("install-electron")
      Write-Output "Companion installed and started by Task Scheduler; it returns at every logon."
      Write-Output "Windows 11 hides new tray icons: click the ^ chevron by the clock, then drag the icon onto the taskbar to pin it."
    } else {
      Invoke-RouterNode "src\tray-service.mjs" @($Action)
    }
  }
}

exit 0
