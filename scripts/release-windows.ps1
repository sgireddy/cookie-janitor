<#
.SYNOPSIS
    One-shot Windows MSI release for Cookie Janitor.

.DESCRIPTION
    Counterpart to scripts/release-mac.sh. Builds the per-user MSI via
    Briefcase + WiX, verifies it, and (optionally) creates a draft
    GitHub Release with the MSI + SHA-256 attached.

    This script is for the day you want to build locally on a Windows
    machine. For routine releases, prefer the CI workflow: pushing a
    `vX.Y.Z` tag triggers .github/workflows/release.yml which builds
    both the DMG and the MSI on hosted runners.

.PARAMETER Rebuild
    Force a fresh build even if dist\*.msi already exists.

.PARAMETER Publish
    Publish the GitHub Release immediately instead of leaving it as a
    draft. NOT recommended until you have smoke-tested the MSI on a
    real Windows install.

.PARAMETER Tag
    Override the tag used. Default: "v<version-from-pyproject>".

.PARAMETER SkipRelease
    Build the MSI and stop. Do not touch GitHub.

.EXAMPLE
    pwsh scripts\release-windows.ps1
    Build the MSI, create a draft GitHub Release, attach the artefacts.

.EXAMPLE
    pwsh scripts\release-windows.ps1 -SkipRelease
    Just produce dist\Cookie-Janitor-x64.msi locally.

.NOTES
    Prerequisites on the build machine:
      * Windows 10 / 11.
      * PowerShell 5.1+ (built-in) or PowerShell 7.
      * Python 3.11 (installed by uv on demand if absent).
      * uv (https://github.com/astral-sh/uv).
      * WiX Toolset v3.x with candle.exe / light.exe on PATH.
        Install via:    choco install wixtoolset
        Or download:    https://github.com/wixtoolset/wix3/releases
      * gh CLI authenticated to GitHub, but only if you let the script
        push a release (i.e. you did NOT pass -SkipRelease).

    The script never writes outside the workspace except for the gh
    release call, which is gated behind explicit confirmation.
#>

[CmdletBinding()]
param(
    [switch]$Rebuild,
    [switch]$Publish,
    [string]$Tag,
    [switch]$SkipRelease
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Write-Step($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    $msg" -ForegroundColor Yellow }

# --- 1. Sanity checks ------------------------------------------------------

Write-Step "Sanity check: tools on PATH"
foreach ($tool in 'uv', 'candle.exe', 'light.exe') {
    if (-not (Get-Command $tool -ErrorAction SilentlyContinue)) {
        throw "Required tool '$tool' not found on PATH. See script docstring for install hints."
    }
}
if (-not $SkipRelease) {
    if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
        throw "gh CLI not found and -SkipRelease was not passed. Either install gh or rerun with -SkipRelease."
    }
}
Write-Ok "All required tools present."

# --- 2. Read version from pyproject.toml ----------------------------------

Write-Step "Reading version from pyproject.toml"
$repoRoot = Split-Path -Parent $PSScriptRoot
Push-Location $repoRoot
try {
    $pyproject = Get-Content "pyproject.toml" -Raw
    if ($pyproject -notmatch '(?ms)^\[project\].*?^\s*version\s*=\s*"(?<v>[^"]+)"') {
        throw "Could not parse version from pyproject.toml"
    }
    $version = $Matches['v']
    if (-not $Tag) { $Tag = "v$version" }
    Write-Ok "Version: $version (tag: $Tag)"

    # --- 3. Build the MSI -------------------------------------------------

    $msiPath = Join-Path $repoRoot "dist\Cookie-Janitor-x64.msi"
    if ((Test-Path $msiPath) -and -not $Rebuild) {
        Write-Step "MSI already exists at $msiPath (pass -Rebuild to force)"
    } else {
        Write-Step "Building MSI via briefcase"
        if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
        if (Test-Path "dist")  { Remove-Item -Recurse -Force "dist"  }

        uv sync --extra dev --extra gui --frozen
        uv pip install "briefcase>=0.3.20,<0.4"
        uv run briefcase create windows app --no-input
        uv run briefcase build windows app --no-input
        uv run briefcase package windows app --adhoc-sign --no-input

        $produced = Get-ChildItem -Path "dist" -Filter *.msi -Recurse | Select-Object -First 1
        if (-not $produced) { throw "Briefcase did not produce an MSI under dist\" }
        if ($produced.FullName -ne $msiPath) {
            Move-Item -Path $produced.FullName -Destination $msiPath -Force
        }
        Write-Ok "MSI: $msiPath ($([math]::Round((Get-Item $msiPath).Length / 1MB, 1)) MB)"
    }

    # --- 4. SHA-256 -------------------------------------------------------

    Write-Step "Computing SHA-256"
    $hash = (Get-FileHash -Algorithm SHA256 -Path $msiPath).Hash.ToLower()
    $name = Split-Path -Leaf $msiPath
    $shaPath = "$msiPath.sha256"
    # Write "<hash>  <filename>" — two spaces — so the file is
    # consumable by `shasum -c` on Unix and round-trips with the CI
    # format. Use ASCII + NoNewline because PowerShell's default UTF-8
    # BOM breaks shasum's parser.
    "$hash  $name" | Out-File -FilePath $shaPath -Encoding ASCII -NoNewline
    Write-Ok "SHA-256: $hash"

    if ($SkipRelease) {
        Write-Step "Done. (-SkipRelease set; not touching GitHub.)"
        return
    }

    # --- 5. Confirm git state ---------------------------------------------

    Write-Step "Checking git state"
    $branch = (git rev-parse --abbrev-ref HEAD).Trim()
    $status = (git status --porcelain).Trim()
    if ($status) {
        Write-Warn "Working tree is dirty:"
        git status --short
        $reply = Read-Host "Continue anyway? [y/N]"
        if ($reply -notmatch '^[Yy]') { throw "Aborted by user." }
    }
    Write-Ok "Branch: $branch"

    # --- 6. Make sure the tag exists -------------------------------------

    $tagExists = $false
    git rev-parse "$Tag" 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { $tagExists = $true }
    if (-not $tagExists) {
        Write-Step "Tag $Tag does not exist locally; creating it"
        git tag -a "$Tag" -m "Cookie Janitor $Tag"
        git push origin "$Tag"
    } else {
        Write-Ok "Tag $Tag exists locally"
    }

    # --- 7. Create / update the draft release ----------------------------

    Write-Step "Creating draft GitHub Release for $Tag"
    $draftFlag = if ($Publish) { @() } else { @('--draft') }

    # gh release create is idempotent-ish: if the release exists, it
    # fails. In that case we upload to the existing one instead.
    $existing = gh release view "$Tag" --json tagName 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Release $Tag already exists; uploading artefacts to it"
        gh release upload "$Tag" "$msiPath" "$shaPath" --clobber
    } else {
        $args = @('release', 'create', $Tag,
                  $msiPath, $shaPath,
                  '--title', "Cookie Janitor $Tag",
                  '--generate-notes') + $draftFlag
        gh @args
    }

    $url = gh release view "$Tag" --json url --jq .url
    Write-Step "Done."
    Write-Ok "Review at: $url"
    if (-not $Publish) {
        Write-Warn "Release is a DRAFT. Click Publish in the GitHub UI after smoke-testing."
    }
} finally {
    Pop-Location
}
