<#
    .SYNOPSIS
    Identifies all Enrollment Agent Certificates in the Machine Context and grants Read Permission to the SCEP Application Pool
    Useful when using custom NDES Service Certificates in Combination with the Built-In Application Pool Identity

    .Notes
    AUTHOR: Uwe Gradenegger

    #Requires -Version 3.0
#>

[cmdletbinding()]
param()

begin {

    New-Variable `
        -Option Constant `
        -Name szOID_ENROLLMENT_AGENT `
        -Value "1.3.6.1.4.1.311.20.2.1"

}

process {

    Get-ChildItem Cert:\LocalMachine\My | 
        Where-Object { $_.EnhancedKeyUsageList.ObjectId -match $szOID_ENROLLMENT_AGENT } | 
            ForEach-Object -Process {

        $CertificateObject = $_

        $PrivateKeyObject = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($CertificateObject)
        $KeyFileName = $PrivateKeyObject.key.UniqueName
        $KeyFilePath = "$env:ALLUSERSPROFILE\Microsoft\Crypto\RSA\MachineKeys\$KeyFileName"

        Try {
            $KeyAcl = Get-Acl -Path $KeyFilePath
        }
        Catch {
            Write-Error -Message "Getting Privatee Key Permissions on Certificate $($CertificateObject.Thumbprint) failed."
            return
        }

        $AclEntry = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "IIS AppPool\SCEP",
            'Read',
            'None',
            'None',
            'Allow'
        )
        $KeyAcl.AddAccessRule($AclEntry)

        Try {
            Set-Acl -Path $KeyFilePath -AclObject $KeyAcl
        }
        Catch {
            Write-Error -Message "Setting Privatee Key Permissions on Certificate $($CertificateObject.Thumbprint) failed."
            return
        }

        # Returning the processed Certificate just to see that something has happened
        $CertificateObject
        
    }

}

end {}