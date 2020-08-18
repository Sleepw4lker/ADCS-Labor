<#
    .Notes
    AUTHOR: Uwe Gradenegger

    #Requires -Version 3.0
#>

[cmdletbinding()]
param()

begin {}

process {

    $Script:BaseDirectory = Split-Path -Path $MyInvocation.MyCommand.Definition -Parent

    (Get-TpmEndorsementKeyInfo).AdditionalCertificates | Foreach-Object -Process {
        Set-Content -Value $_.RawData -Encoding Byte -Path "$($Script:BaseDirectory)\$($_.Thumbprint).crt" -Force
    }

}

end {}