#Requires -Modules @{ ModuleName="PSCertificateEnrollment"; ModuleVersion="1.0.6" },@{ ModuleName="WebAdministration"; ModuleVersion="1.0.0.0" }

[cmdletbinding()]
param(
    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $CepEncryptionTemplate,

    [Parameter(Mandatory=$True)]
    [ValidateNotNullOrEmpty()]
    [String]
    $EnrollmentAgentTemplate,

    [Parameter(Mandatory=$True)]
    [ValidateRange(1,3650)]
    [Int]
    $Days = 90,

    [Alias("CryptographicServiceProvider")]
    [Parameter(Mandatory=$False)]
    [ValidateScript({
        $Csp = $_
        [bool](Get-KeyStorageProvider | Where-Object { $_.Name -eq $Csp }).LegacyCsp
    })]
    [String]
    $Csp = "Microsoft Strong Cryptographic Provider"
)

begin {

    New-Variable -Option Constant -Name szOID_CERTIFICATE_TEMPLATE -Value "1.3.6.1.4.1.311.21.7"
    New-Variable -Option Constant -Name XCN_CRYPT_STRING_BASE64 -Value 1

    New-Variable -Option Constant -Name DispositionType -Value @{
        CR_DISP_INCOMPLETE = 0
        CR_DISP_ERROR = 1
        CR_DISP_DENIED = 2
        CR_DISP_ISSUED = 3
        CR_DISP_ISSUED_OUT_OF_BAND = 4
        CR_DISP_UNDER_SUBMISSION = 5
        CR_DISP_REVOKED = 6
    }

    function Get-TemplateOidFromRegistry {

        param(
            [Parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [String]
            $Name
        )

        return (Get-Itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\CertificateTemplateCache\$Name" -ErrorAction SilentlyContinue)."msPKI-Cert-Template-OID"
    }

    function Get-NdesRaCertificate {

        param(
            [Parameter(Mandatory=$True)]
            [ValidatePattern("^[\.0-9]*$")]
            [String]
            $Oid,

            [Parameter(Mandatory=$False)]
            [ValidateRange(1,3650)]
            [Int]
            $Days = 90
        )

        Get-ChildItem -Path Cert:\LocalMachine\My |
            Where-Object { $_.NotAfter -gt ((Get-Date).AddDays($Days)) } |
                ForEach-Object -Process {

            $CurrentCertificate = $_

            $TemplateExtension =  $CurrentCertificate.Extensions | Where-Object { $_.Oid.Value -eq $szOID_CERTIFICATE_TEMPLATE }

            If ($null -ne $TemplateExtension) {
                $ExtensionData = New-Object -ComObject "X509Enrollment.CX509ExtensionTemplate"
                $ExtensionData.InitializeDecode($XCN_CRYPT_STRING_BASE64, [Convert]::ToBase64String( $TemplateExtension.RawData ))
                If ($ExtensionData.TemplateOid.Value -eq $Oid) {
                     $CurrentCertificate 
                     }
            }
        }
    }

    function Set-PrivateKeyPermissions {

        param(
            [Parameter(Mandatory=$True, ValuefromPipeline=$True)]
            [System.Security.Cryptography.X509Certificates.X509Certificate]
            $Certificate,

            [Parameter(Mandatory=$False)]
            [string]
            $Principal = "IIS AppPool\SCEP"
        )

        $Certificate = Get-ChildItem -Path Cert:\LocalMachine\My\$($Certificate.Thumbprint)

        $PrivateKeyObject = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        $KeyFileName = $PrivateKeyObject.Key.UniqueName
        $KeyFilePath = "$env:ALLUSERSPROFILE\Microsoft\Crypto\RSA\MachineKeys\$KeyFileName"
        $KeyAcl = Get-Acl -Path $KeyFilePath

        $AclEntry = New-Object System.Security.AccessControl.FileSystemAccessRule($Principal, 'Read', 'None', 'None', 'Allow')
        $KeyAcl.AddAccessRule($AclEntry)

        Write-Verbose -Message "Granting Read Permission for $Principal on Certificate $($Certificate.Thumbprint), $KeyFileName under $KeyFilePath"
        Set-Acl -Path $KeyFilePath -AclObject $KeyAcl
    }
}

process {

    # Prevent usage on PowerShell Core
    If ($PSVersionTable.PSEdition -ne "Desktop") {
        Write-Error -Message "This is only compatible with the Desktop Edition of Windows PowerShell"
        return
    }

    # Ensuring the Script will be run with Elevation
    If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error -Message "This must be run as Administrator! Aborting."
        return
    }

    # Abort if NDES is not installed
    $ConfigString = (Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP\CAInfo -Name Configuration -ErrorAction SilentlyContinue).Configuration
    If ($null -eq $ConfigString) {
        Write-Error -Message "This host does not seem to have NDES installed. Aborting."
        return
    }

    $RestartRequired = $False

    $TemplateCollection =
        [PSCustomObject]@{
            Name = $EnrollmentAgentTemplate
            KeyUsage = "DigitalSignature"
            Csp = $Csp
        },
        [PSCustomObject]@{
            Name = $CepEncryptionTemplate
            KeyUsage = "KeyEncipherment"
            Csp = $Csp
        }

    ForEach ($CurrentTemplate in $TemplateCollection) {

        If (Get-NdesRaCertificate -Oid (Get-TemplateOidFromRegistry -Name $CurrentTemplate.Name) -Days $Days) {
            Write-Verbose -Message "Found a valid certificate for $($CurrentTemplate.Name)"
            continue
        }

        Write-Verbose -Message "Requesting certificate for $($CurrentTemplate.Name) template from $ConfigString"

        $CertificateRequest = New-CertificateRequest `
            -Subject "CN=$env:ComputerName" `
            -MachineContext `
            -Ksp $CurrentTemplate.Csp `
            -KeyLength 4096 `
            -KeyUsage $CurrentTemplate.KeyUsage

        $SubmissionResponse = $CertificateRequest | Get-IssuedCertificate `
            -ConfigString $ConfigString `
            -CertificateTemplate $CurrentTemplate.Name

        If ($SubmissionResponse.Disposition -ne $DispositionType.CR_DISP_ISSUED) {
            Write-Warning -Message "Unable to retrieve certificate for $($CurrentTemplate.Name) from $($ConfigString): $($SubmissionResponse.StatusMessage)"
            continue
        }

        $SubmissionResponse.Certificate | Install-IssuedCertificate -MachineContext -Force | Out-Null
        $SubmissionResponse.Certificate | Set-PrivateKeyPermissions

        $RestartRequired = $True        
    }

    If ($RestartRequired) {

        Restart-WebAppPool -Name SCEP
        Start-Sleep -Seconds 15
        [void](Invoke-WebRequest -Uri "http://localhost/certsrv/mscep/mscep.dll/pkiclient.exe?operation=GetCACaps" -UseBasicParsing)
    }

}

end {}