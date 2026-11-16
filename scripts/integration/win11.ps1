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
# Доступно: $src — проверяемый коммит, $box — песочница.
function Invoke-Checks {
    Step 'files' { Test-Path -LiteralPath (Join-Path $src 'go.mod') -PathType Leaf }
}

$ErrorActionPreference = 'Continue' # 'Stop' в Windows PowerShell 5.1 обрывает git на первой строке stderr
$box = $null; $log = $null; $src = $null; $stepName = 'start'; $result = $null; $installed = @()

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

try {
    $stepName = 'admin'
    if ($NeedAdmin -and -not (Test-Admin)) { throw 'admin' }

    $stepName = 'sandbox'
    $box = Join-Path ([IO.Path]::GetTempPath()) ('xm-check-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $box -ErrorAction Stop | Out-Null
    foreach ($d in 'tmp', 'cache', 'go') { New-Item -ItemType Directory -Path (Join-Path $box $d) -ErrorAction Stop | Out-Null }
    $log = Join-Path $box 'log'
    $src = Join-Path $box 'src'
    $env:TEMP = Join-Path $box 'tmp'; $env:TMP = $env:TEMP
    $env:GOPATH = Join-Path $box 'go'; $env:GOMODCACHE = Join-Path $box 'go\mod'
    $env:GOCACHE = Join-Path $box 'cache\go'; $env:GOTOOLCHAIN = 'auto'; $env:GIT_TERMINAL_PROMPT = '0'

    foreach ($t in $Tools) {
        if (Get-Command $t.Cmd -ErrorAction SilentlyContinue) { continue }
        Step 'tools' { winget install --id $t.Winget --exact --silent --accept-package-agreements --accept-source-agreements --disable-interactivity }
        $installed += $t.Winget
        $env:Path = [Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' + [Environment]::GetEnvironmentVariable('Path', 'User')
        Step 'tools' { [bool](Get-Command $t.Cmd -ErrorAction SilentlyContinue) }
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
    $state = 'clean'
    foreach ($id in $installed) {
        $global:LASTEXITCODE = 0
        winget uninstall --id $id --exact --silent --disable-interactivity *> $null
        if ($LASTEXITCODE -ne 0) { $state = 'dirty' }
    }
    if ($box -and (Test-Path -LiteralPath $box)) {
        Remove-Item -LiteralPath $box -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $box) { $state = 'dirty' }
    }
    if (-not $result) { $result = "FAIL $stepName" }
    Write-Output ('XM-CHECK {0} {1} {2} {3}' -f $CheckId, $Commit.Substring(0, 7), $result, $state)
}
