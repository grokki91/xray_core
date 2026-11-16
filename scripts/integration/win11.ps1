# Каркас скрипта проверки на реальной интеграции для Windows 11 (Windows PowerShell 5.1).
# Контракт — docs/dev/integration-check.md. Субагент integration-check меняет только параметры
# ниже и тело Invoke-Checks; остальное — общее для всех проверок.
#
# Что делает: песочница во временном каталоге → недостающие программы через winget →
# проверяемый коммит по SHA → шаги Invoke-Checks → удаление установленного и песочницы. Вывод
# шагов идёт в журнал песочницы и удаляется вместе с ней; в консоль — ровно одна строка:
#   XM-CHECK <CheckId> <SHA7> PASS|FAIL <шаг> clean|dirty
$CheckId = 'example-1'                                  # имя проверки; новая версия — новый суффикс
$RepoUrl = 'https://github.com/grokki91/xray_core.git'  # публичный репозиторий проекта
$Commit = '0000000000000000000000000000000000000000'     # полный SHA проверяемого коммита
$NeedAdmin = $false                                     # $true — шагам нужен администратор
$Tools = @(@{ Cmd = 'git'; Winget = 'Git.Git' })        # команда и идентификатор пакета winget

# Шаги проверки: Step '<имя>' { … }. Шаг провален, если блок бросил исключение, внешняя
# программа вернула ненулевой код, командлет записал ошибку или последнее значение — $false.
# Доступно: $src — проверяемый коммит, $box — песочница. Ссылок из песочницы наружу шаги не создают.
function Invoke-Checks {
    Step 'files' { Test-Path -LiteralPath (Join-Path $src 'go.mod') -PathType Leaf }
}

$ErrorActionPreference = 'Continue' # 'Stop' в Windows PowerShell 5.1 обрывает git на первой строке stderr
$log = $null; $src = $null; $stepName = 'start'; $result = $null; $installed = @(); $saved = @{}; $unknown = $false
$tempRoot = [IO.Path]::GetTempPath()
Set-Variable -Name box -Scope Script -Value $null

function Step([string]$Name, [scriptblock]$Body) {
    $script:stepName = $Name
    $global:LASTEXITCODE = 0
    $out = @(& $Body 2>&1)
    $out | Out-File -LiteralPath $script:log -Append -Encoding utf8
    $errors = @($out | Where-Object { $_ -is [Management.Automation.ErrorRecord] -and $_.FullyQualifiedErrorId -notlike 'NativeCommandError*' })
    if ($LASTEXITCODE -ne 0 -or $errors.Count -gt 0) { throw $Name }
    if ($out.Count -gt 0 -and $out[-1] -is [bool] -and -not $out[-1]) { throw $Name }
}
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Test-Package([string]$Id) { # установлен ли пакет — по winget, а не по PATH
    $global:LASTEXITCODE = 0
    winget list --id $Id --exact --accept-source-agreements --disable-interactivity *> $null
    if ($LASTEXITCODE -eq 0) { return $true }
    if ($LASTEXITCODE -eq -1978335212) { return $false } # 0x8A150014: пакет не найден
    throw 'tools' # сбой winget — неизвестно, стоит ли пакет; ничего не ставить и не удалять
}
function Remove-Tree([string]$Path) { # без оболочки; ссылки и точки соединения — удалить саму ссылку
    foreach ($i in ([IO.DirectoryInfo]$Path).GetFileSystemInfos()) {
        if ($i.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            if ($i -is [IO.DirectoryInfo]) { [IO.Directory]::Delete($i.FullName, $false) } else { $i.Delete() }
        } elseif ($i -is [IO.DirectoryInfo]) { Remove-Tree $i.FullName } else {
            $i.Attributes = [IO.FileAttributes]::Normal
            $i.Delete()
        }
    }
    [IO.Directory]::Delete($Path, $false)
}
function Set-BoxEnv([hashtable]$Vars) { # прежние значения — в $saved, возвращаются в finally
    foreach ($k in $Vars.Keys) {
        if (-not $script:saved.ContainsKey($k)) { $script:saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process') }
        [Environment]::SetEnvironmentVariable($k, $Vars[$k], 'Process')
    }
}

try {
    $stepName = 'admin'
    if ($NeedAdmin -and -not (Test-Admin)) { throw 'admin' }

    $stepName = 'sandbox'
    Set-Variable -Name box -Scope Script -Option ReadOnly -Force -Value (Join-Path $tempRoot ('xm-check-' + [guid]::NewGuid().ToString('N').Substring(0, 8)))
    New-Item -ItemType Directory -Path $box -ErrorAction Stop | Out-Null
    foreach ($d in 'tmp', 'home', 'appdata', 'localappdata', 'cache', 'go') { New-Item -ItemType Directory -Path (Join-Path $box $d) -ErrorAction Stop | Out-Null }
    $log = Join-Path $box 'log'
    $src = Join-Path $box 'src'

    # Ставится только отсутствующее по winget; уже установленное не обновляется и не удаляется.
    foreach ($t in $Tools) {
        if (Get-Command $t.Cmd -ErrorAction SilentlyContinue) { continue }
        $stepName = 'tools'
        if (Test-Package $t.Winget) { throw 'tools' } # стоит, но не в PATH — не трогаем
        try {
            Step 'tools' { winget install --id $t.Winget --exact --silent --no-upgrade --accept-package-agreements --accept-source-agreements --disable-interactivity }
        } finally {
            $stepName = 'tools'
            try { if (Test-Package $t.Winget) { $installed += $t.Winget } } catch { $unknown = $true }
        }
        Set-BoxEnv @{ Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User') }
        Step 'tools' { [bool](Get-Command $t.Cmd -ErrorAction SilentlyContinue) }
    }

    # Конфигурация владельца (git, go) не читается, кэши и временные файлы — только в песочнице.
    Set-BoxEnv @{
        TEMP = (Join-Path $box 'tmp'); TMP = (Join-Path $box 'tmp'); HOME = (Join-Path $box 'home')
        APPDATA = (Join-Path $box 'appdata'); LOCALAPPDATA = (Join-Path $box 'localappdata')
        GOPATH = (Join-Path $box 'go'); GOMODCACHE = (Join-Path $box 'go\mod'); GOCACHE = (Join-Path $box 'cache\go')
        GOENV = 'off'; GOTOOLCHAIN = 'auto'; GOFLAGS = $null; GOPROXY = $null; GOSUMDB = $null; GONOSUMDB = $null
        GONOPROXY = $null; GOPRIVATE = $null; GOINSECURE = $null
        GIT_CONFIG_GLOBAL = 'NUL'; GIT_CONFIG_NOSYSTEM = '1'; GIT_TERMINAL_PROMPT = '0'
    }

    Step 'fetch' { git init -q $src }
    Step 'fetch' { git -C $src fetch -q --depth 1 $RepoUrl $Commit }
    Step 'fetch' { git -C $src -c advice.detachedHead=false checkout -q FETCH_HEAD }
    Step 'commit' { (git -C $src rev-parse HEAD) -eq $Commit }
    Invoke-Checks
    $result = 'PASS'
} catch {
    # Причина — имя шага в $stepName; текст ошибки остаётся в журнале и удаляется с песочницей.
} finally {
    $state = if ($unknown) { 'dirty' } else { 'clean' }
    foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
    foreach ($id in $installed) {
        $global:LASTEXITCODE = 0
        winget uninstall --id $id --exact --silent --disable-interactivity *> $null
        if ($LASTEXITCODE -ne 0) { $state = 'dirty' }
    }
    if ($box -and $box -like (Join-Path $tempRoot 'xm-check-*') -and (Test-Path -LiteralPath $box)) {
        try { Remove-Tree $box } catch { }
    }
    if ($box -and (Test-Path -LiteralPath $box)) { $state = 'dirty' }
    if (-not $result) { $result = "FAIL $stepName" }
    Write-Output ('XM-CHECK {0} {1} {2} {3}' -f $CheckId, $Commit.Substring(0, 7), $result, $state)
}
