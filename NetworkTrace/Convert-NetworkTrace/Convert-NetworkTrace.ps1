$DirInput = ".\input"
$DirOutput = ".\output"
$DirArchive = ".\done"

Get-ChildItem $DirInput -Filter *.etl | ForEach-Object -Process {

    $FileInput = $_.FullName
    $FileOutput = ($FileIn.Replace($DirInput, $DirOutput)).Replace(".etl",".cap")
    $FileArchive = $FileIn.Replace($DirInput, $DirArchive)

    $PefTraceSession = New-PefTraceSession -Path $FileOutput -SaveOnStop
    $PefTraceSession | Add-PefMessageProvider -Provider $FileInput
    $PefTraceSession | Start-PefTraceSession

    Move-Item -Path $FileInput -Destination $FileArchive

}