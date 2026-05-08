[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
    [string]
    $fileName
)

$snippets = Get-Content -Path $fileName -Raw | ConvertFrom-Json


Write-Output "| Trigger | Content |`n| --- | --- |"

$snippets | Get-Member -MemberType NoteProperty | ForEach-Object {
    $snippetName = $_.name
    $prefix = $snippets.$snippetName.prefix

    Write-Output "| ``$prefix`` | $snippetName |"
}
