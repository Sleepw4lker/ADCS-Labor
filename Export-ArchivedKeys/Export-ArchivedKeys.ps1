[cmdletbinding()]
param()

$Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

# Loading all Libary Scripts we depend on
Get-ChildItem -Path "$Script:BaseDirectory\lib" -Filter *.ps1 | ForEach-Object {
    . ($_.FullName)
}

$WorkFolder = "$Script:BaseDirectory\$(Get-Date -Format yyyyMMdd_hhmmss)"

If (-not (Test-Path $WorkFolder)) {
    [void](mkdir $WorkFolder)
}

# Identify all Certificates that have archived private Keys associated
certutil -view -restrict "KeyRecoveryHashes>0" -out RequestId,RequesterName,SerialNumber,NotBefore,NotAfter,KeyRecoveryHashes csv  > "$WorkFolder\SerialNumbers.csv"

Import-Csv -Path "$WorkFolder\SerialNumbers.csv" | ForEach-Object -Process {

    $OutputObject = $_
    $SerialNumber = $_."Serial Number"

    # Retrieve the archived Key Blobs from the CA
    Write-Verbose -Message "Writing archived Key to $SerialNumber.bin"
    certutil -getkey $_."Serial Number" "$WorkFolder\$($SerialNumber).bin"

    # Generate a Random Password
    $Password = New-RandomPassword -PasswordLength 16

    # Write all the necessary Information to a CSV for easier Import into Excel or KeePass later on
    Add-Member `
        -InputObject $OutputObject `
        -MemberType NoteProperty `
        -Name "Password" `
        -Value $Password `
        -Force

    $OutputObject | Export-Csv -Path "$WorkFolder\ExportedKeys.csv" -Force -NoTypeInformation -Encoding UTF8 -Append

    # Perform the Recovery and save to a PFX File with a Random Password
    Write-Verbose -Message "Writing Certificate to $SerialNumber.pfx"
    certutil -p "$Password" -recoverkey "$WorkFolder\$($SerialNumber).bin" "$WorkFolder\$($SerialNumber).pfx"
    
}