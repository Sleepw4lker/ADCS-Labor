[cmdletbinding()]
param()

Function New-RandomPassword {

    [cmdletbinding()]
    param (
        [ValidateRange(3, 128)]
        [int]
        $PasswordLength = 8
    )

    process {

        # https://activedirectoryfaq.com/2017/08/creating-individual-random-passwords/
        
        function Get-RandomCharacters {

            param(
                $length, $characters
            )

            $random = 1..$length | ForEach-Object { Get-Random -Maximum $characters.length } 
            $private:ofs="" 

            return [String]$characters[$random]
        }

        function Get-RandomizedString {

            param(
                [string]$inputString
            )

            $characterArray = $inputString.ToCharArray()   
            $scrambledStringArray = $characterArray | Get-Random -Count $characterArray.Length     
            $outputString = -join $scrambledStringArray

            return $outputString 
        }

        $password = Get-RandomCharacters -length ($PasswordLength - 3) -characters 'abcdefghiklmnoprstuvwxyz'
        $password += Get-RandomCharacters -length 1 -characters 'ABCDEFGHKLMNOPRSTUVWXYZ'
        $password += Get-RandomCharacters -length 1 -characters '1234567890'
        $password += Get-RandomCharacters -length 1 -characters '!§$%&/()=?}][{@#*+'

        $password = Get-RandomizedString -inputString $password

        return $password

    }
    
}

$Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

$WorkFolder = "$Script:BaseDirectory\$(Get-Date -Format yyyyMMdd_hhmmss)"

If (-not (Test-Path $WorkFolder)) {
    [void](mkdir "$WorkFolder")
    [void](mkdir "$WorkFolder\bin")
    [void](mkdir "$WorkFolder\pfx")
    [void](mkdir "$WorkFolder\logs")
}

# Identify all Certificates that have archived private Keys associated
$Header = "RequestId","RequesterName","SerialNumber","NotBefore","NotAfter","KeyRecoveryHashes"

# Converting the Array to a Comma separated List, for certutil
For ($i = 0; $i -lt $Header.Count; $i++) {

    If ($i -eq 0) {
        $Out = $Header[$i]
    }
    Else {
        $Out = "$Out,$($Header[$i])"
    }

}

$AffectedRows = certutil -view -restrict "KeyRecoveryHashes>0" -out $Out csv

If ($AffectedRows.count -gt 1) {

    # We have the problem that Field Headers are localized
    # But we have the -Header Parameter for ConvertFrom-Csv and Import-Csv so we can make our own

    # Deleting the original Header
    $AffectedRows = $AffectedRows[1..($AffectedRows.count - 1)]

    # Re-Importing and Using our own Headers
    $AffectedRows = $AffectedRows | ConvertFrom-Csv -Header $Header

    $AffectedRows | Export-Csv `
        -Path "$WorkFolder\SerialNumbers.csv" `
        -Force `
        -NoTypeInformation `
        -Encoding UTF8

    $ResultArray = @()

    Import-Csv -Path "$WorkFolder\SerialNumbers.csv" | ForEach-Object -Process {

        $OutputObject = $_
        $SerialNumber = $_."SerialNumber"

        # Retrieve the archived Key Blobs from the CA
        Write-Verbose -Message "Writing archived Key to $SerialNumber.bin"
        certutil -getkey $SerialNumber "$WorkFolder\bin\$($SerialNumber).bin" |
            Out-File -FilePath "$WorkFolder\logs\$($SerialNumber)_getkey.txt"

        If ($LASTEXITCODE -ne 0) {

            $ResultString = "Failed to retrieve encrypted Key from CA"

        }
        Else {

            # Generate a Random Password
            $Password = New-RandomPassword -PasswordLength 16

            # Perform the Recovery and save to a PFX File with a Random Password
            Write-Verbose -Message "Writing Certificate to $SerialNumber.pfx"
            certutil -p "$Password" -recoverkey "$WorkFolder\bin\$($SerialNumber).bin" "$WorkFolder\pfx\$($SerialNumber).pfx" | 
                Out-File -FilePath "$WorkFolder\logs\$($SerialNumber)_recoverkey.txt"

            If ($LASTEXITCODE -ne 0) {
                $ResultString = "Failed to recover Key"
            }
            Else {
                $ResultString = "Success"
            }

            # Write all the necessary Information to a CSV for easier Import into Excel or KeePass later on
            Add-Member `
                -InputObject $OutputObject `
                -MemberType NoteProperty `
                -Name "Password" `
                -Value $Password `
                -Force

            Add-Member `
                -InputObject $OutputObject `
                -MemberType NoteProperty `
                -Name "Result" `
                -Value $ResultString `
                -Force

            $ResultArray += $OutputObject

        }
        
    }

    $ResultArray | Export-Csv `
        -Path "$WorkFolder\ExportedKeys.csv" `
        -Force `
        -NoTypeInformation `
        -Encoding UTF8

}