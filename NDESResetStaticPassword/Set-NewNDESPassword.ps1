#Requires -Modules @{ ModuleName="WebAdministration"; ModuleVersion="1.0.0.0" }

[cmdletbinding()]
param()

begin {}

process {

    # Prevent usage on PowerShell Core
    if ($PSVersionTable.PSEdition -ne "Desktop") {
        Write-Error -Message "This is only compatible with the Desktop Edition of Windows PowerShell"
        return
    }

    # Ensuring the Script will be run with Elevation
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error -Message "This must be run as Administrator! Aborting."
        Return
    }

    # Abort if NDES is not installed
    if ($null -eq (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\CAInfo -Name Configuration -ErrorAction).Configuration) {
        Write-Error -Message "This host does not seem to have NDES installed. Aborting."
    }

    # Deletes the EncryptedPassword from NDES Registry
    Remove-ItemProperty `
        -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\EncryptedPassword `
        -Name EncryptedPassword

    # Reloads IIS App Pool for NDES
    Restart-WebAppPool -Name SCEP

    # Lets wait some seconds
    Start-Sleep -Seconds 15

    # Trigger Start of NDES Service, thus generating a new EncryptedPassword
    [void](Invoke-WebRequest -Uri "http://localhost/certsrv/mscep/mscep.dll/pkiclient.exe?operation=GetCACaps")

}

end {}