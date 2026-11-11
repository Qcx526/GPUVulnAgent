$ErrorActionPreference = 'SilentlyContinue'

Write-Output '=== nvJPEG DLL search ==='

$roots = @(
  'C:\Program Files\NVIDIA GPU Computing Toolkit',
  'C:\Program Files\NVIDIA Corporation',
  'C:\Program Files\NVIDIA',
  'C:\ProgramData\NVIDIA',
  'C:\Windows\System32',
  'C:\Windows\SysWOW64',
  'C:\Program Files\Python312',
  'C:\Program Files\Python311',
  'C:\Python312',
  'C:\ProgramData\anaconda3',
  'C:\ProgramData\miniconda3'
)

foreach ($r in $roots) {
  if (Test-Path -LiteralPath $r) {
    Get-ChildItem -LiteralPath $r -Recurse -Filter 'nvjpeg*.dll' -File |
      ForEach-Object {
        Write-Output ('{0}|{1}|{2}|{3}' -f $_.FullName, $_.Length, $_.VersionInfo.FileVersion, $_.LastWriteTime.ToString('yyyy-MM-dd'))
      }
  }
}

Write-Output '=== CUDA toolkit versions present ==='
$cuda = 'C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA'
if (Test-Path -LiteralPath $cuda) {
  Get-ChildItem -LiteralPath $cuda -Directory | ForEach-Object { Write-Output $_.FullName }
}

Write-Output '=== NVJPEG env vars ==='
Get-ChildItem Env: | Where-Object { $_.Name -match 'CUDA|NVJPEG|NVIDIA' } | ForEach-Object { Write-Output ('{0}={1}' -f $_.Name, $_.Value) }

Write-Output '=== nvcc / cuda headers ==='
$hdr = Get-ChildItem -LiteralPath $cuda -Recurse -Filter 'nvjpeg.h' -File | ForEach-Object { $_.FullName }
if ($hdr) { $hdr | ForEach-Object { Write-Output $_ } } else { Write-Output 'nvjpeg.h NOT FOUND' }
