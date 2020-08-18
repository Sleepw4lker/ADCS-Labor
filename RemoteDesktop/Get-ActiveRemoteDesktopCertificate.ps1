<#
    .Notes
    AUTHOR: Uwe Gradenegger

    #Requires -Version 3.0
#>

[cmdletbinding()]
param()

begin {}

process {

    $RdcCertHash = (Get-WmiObject `
        -Class "Win32_TSGeneralSetting" `
        -Namespace root\cimv2\terminalservices `
        -Filter "TerminalName='RDP-tcp'"
        ).SSLCertificateSHA1Hash

    Get-ChildItem -Path Cert:\LocalMachine\My | 
        Where-Object { $_.Thumbprint -eq $RdcCertHash }

    }

end {}