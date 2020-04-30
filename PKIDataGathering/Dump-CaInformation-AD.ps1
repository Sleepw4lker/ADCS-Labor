<#
    .SYNOPSIS
    Exports Active Directory Certificate Services Configuration Data from Active Directory
    Run this once on a Domain Controller (or any other 8.0/2012+ Machine) with AD Powershell Module installed

    .PARAMETER DumpCA
    Tries to connect to each Certification Authority that is found in Active Directory and collects config data.
    You need Network connectivitiy and "Read" Permission on each CA to use this.

    .PARAMETER DsConfigDn
    Manually specifies the Directory Service Configuration DN. Used if the Script is ran across a forest trust.
    In most cases, this Parameter is not required.

    .PARAMETER Path
    Path for the Configuration dump. If not specified, the Path of the Script File is used.

   .Notes
    AUTHOR: Uwe Gradenegger

    #Requires -Version 3.0

#>
[cmdletbinding()]
param (
    [Parameter(Mandatory=$False)]
    [Switch]
    $DumpCA = $False,

    [Parameter(Mandatory=$False)]
    [String]
    $Path = $(Split-Path -Path $MyInvocation.MyCommand.Definition -Parent),

    [Parameter(Mandatory=$False)]
    [String]
    $DsConfigDn = $null
)

<#
To Do:
- Implement Support for Client Operating Systems (RSAT is detected differently)
- Improve Error Handling
- Detection for local CA Installation/to merge both Scripts into one File
- Put ADCS Connectivity Test in a meaningful Function
- Merge AIA and Certification Authorities Dump
- Dump ACLs as these seem not to be exported with certutil -ds in Windows 2012
#>

#region Test-Prerequisites

# Ensuring the Script will be run on a supported Operating System
$OS = Get-WmiObject -Class Win32_OperatingSystem
If (($OS.name -notmatch "Server") -or ([int32]$OS.BuildNumber -lt 9200)) {
    Write-Warning -Message "This Script must be run on Windows Server 2012 or newer! Aborting."
    return 
}

# Ensuring we have required AD PowerShell Modules installed
If ((Get-WindowsFeature RSAT-AD-PowerShell).Installed -ne $True) {
    Write-Warning -Message "This Script requires AD PowerShell Modules (RSAT-AD-PowerShell) to be installed! Aborting."
    return 
}

#endregion Test-Prerequisites

#region Functions

Function Remove-InvalidFileNameChars {

    [cmdletbinding()]
    param(
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]$Name
    )

    $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
    $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
    return ($Name -replace $re)
}

#endregion Functions

#region Preparations

Import-Module ActiveDirectory
If ($null -eq $DsConfigDn) {
    $DsConfigDn = "CN=Configuration,$($(Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain).DistinguishedName)"
}

[void](New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop)

#endregion Preparations

#region Dump-AIA

$CurrentDirectory = "$Path\AIA"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=AIA,CN=Public Key Services,CN=Services,$DsConfigDn" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName
    Write-Verbose -Message "Dumping $ObjectDn"

    # Windows 2012/R2 do not seem to support specifying further Arguments
    certutil -v -ds $ObjectDn > "$CurrentDirectory\certificationAuthority_$($ObjectName).txt"

    $i = 0
    $(Get-ADObject $_ -Properties cACertificate).cACertificate | Foreach-Object {
        $FileName = "$CurrentDirectory\$($ObjectName)_cACertificate_($($i))"
        # CRT Files are usually blocked by E-Mail Anti-Virus, thus only exporting in BASE64 Encoding to Text Files
        Set-Content `
            -Value "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($_))`n-----END CERTIFICATE-----" `
            -Encoding UTF8 `
            -Path "$($FileName)_BASE64.txt" `
            -Force
        certutil -dump "$($FileName)_BASE64.txt" > "$($FileName)_BASE64_dump.txt"
        $i++
    }

}

#endregion Dump-AIA

#region Dump-CDP

Get-ChildItem "AD:CN=CDP,CN=Public Key Services,CN=Services,$DsConfigDn" | Foreach-Object -Process {

    $ObjectName = $_.Name

    $CurrentDirectory = "$Path\CDP\$($ObjectName)"
    [void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

    # Enumerate Sub Directories
    Get-ChildItem "AD:$($_.DistinguishedName)" | Foreach-Object -Process {

        $ObjectName = $_.Name
        $ObjectDn = $_.DistinguishedName

        Write-Verbose -Message "Dumping $ObjectDn"

        certutil -v -ds $ObjectDn > "$CurrentDirectory\cRLDistributionPoint_$($ObjectName).txt"

        $Crl = $(Get-ADObject $_ -Properties certificateRevocationList).certificateRevocationList
        If ($Crl.Length -gt 1) {
            $FileName = "$CurrentDirectory\$($ObjectName)_certificateRevocationList"
            Set-Content `
                -Value $Crl `
                -Encoding Byte `
                -Path "$($FileName).crl" `
                -Force `
                -ErrorAction SilentlyContinue
        }
        
        $DeltaCrl = $(Get-ADObject $_ -Properties deltaRevocationList).deltaRevocationList
        If ($DeltaCrl.Length -gt 1) {
            $FileName = "$CurrentDirectory\$($ObjectName)_deltaRevocationList"
            Set-Content `
                -Value $DeltaCrl `
                -Encoding Byte `
                -Path "$($FileName)+.crl" `
                -Force `
                -ErrorAction SilentlyContinue
        }

    }

}

#endregion Dump-CDP

# region Dump-CertificateTemplates

$CurrentDirectory = "$Path\Certificate Templates"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=Certificate Templates,CN=Public Key Services,CN=Services,$DsConfigDn" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName
    Write-Verbose -Message "Dumping $ObjectDn"

    $TemplateName = Remove-InvalidFileNameChars $($ObjectName)
    certutil -v -template $TemplateName > "$CurrentDirectory\pKICertificateTemplate_$($TemplateName).txt"

}

# region Dump-CertificateTemplates

#region Dump-CertificationAuthorities

$CurrentDirectory = "$Path\Certification Authorities"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=Certification Authorities,CN=Public Key Services,CN=Services,$DsConfigDn" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName
    Write-Verbose -Message "Dumping $ObjectDn"

    # Windows 2012/R2 do not seem to support specifying further Arguments
    certutil -v -ds $ObjectDn > "$CurrentDirectory\certificationAuthority_$($ObjectName).txt"

    $i = 0
    $(Get-ADObject $_ -Properties cACertificate).cACertificate | Foreach-Object {
        $FileName = "$CurrentDirectory\$($ObjectName)_cACertificate_($($i))"
        # CRT Files are usually blocked by E-Mail Anti-Virus, thus only exporting in BASE64 Encoding to Text Files
        Set-Content `
            -Value "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($_))`n-----END CERTIFICATE-----" `
            -Encoding UTF8 `
            -Path "$($FileName)_BASE64.txt" `
            -Force
        certutil -dump "$($FileName)_BASE64.txt" > "$($FileName)_BASE64_dump.txt"
        $i++
    }

}

#endregion Dump-CertificationAuthorities

#region Dump-EnrollmentServices

$CurrentDirectory = "$Path\Enrollment Services"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=Enrollment Services,CN=Public Key Services,CN=Services,$DsConfigDn" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName

    Write-Verbose -Message "Dumping $ObjectDn"

    # Windows 2012/R2 do not seem to support specifying further Arguments
    certutil -v -ds $ObjectDn > "$CurrentDirectory\pKIEnrollmentService_$($ObjectName).txt"

    $DnsHostName = $(Get-ADObject $_ -Properties dNSHostName).dNSHostName

    # Dumping which Certificate Templates are bound to each CA
    (Get-ADObject $_ -Properties certificateTemplates).certificateTemplates |
        Out-File -FilePath "$CurrentDirectory\$($ObjectName)_CATemplates.txt" -Encoding String -Force

    If ($DumpCA) {

        Write-Verbose -Message "Dumping Configuration from $ObjectName ($DnsHostName)"

        # TestICertAdmin Connectivity First to speed up Process, throw Error on Fail
        $CertAdmin = New-Object -ComObject CertificateAuthority.Admin.1

        Try {
            [void]($CertAdmin.GetCAProperty("$DnsHostName\$ObjectName",0x6,0,4,0))
            $CaIsOnline = $True
        }
        Catch {
            Write-Warning -Message "Cannot connect to $ObjectName ($DnsHostName)"
            Write-Warning -Message "Configuration therefore not exported. Do this manually directly on the CA."
            $CaIsOnline = $False
        }

        If ($CaIsOnline -eq $True) {

            $Now = $((Get-Date).ToString($(Get-culture).DateTimeFormat.ShortDatePattern))
            $DbFields = "RequestID,SerialNumber,RequesterName,CommonName,CertificateTemplate,NotBefore,NotAfter"

            # Dumping CA Configuration
            certutil -config "$DnsHostName\$ObjectName" -v -getreg CA > "$CurrentDirectory\$($ObjectName)_getreg_CA.txt"
            certutil -config "$DnsHostName\$ObjectName" -v -getreg CA\CSP > "$CurrentDirectory\$($ObjectName)_getreg_CA_CSP.txt"
            certutil -config "$DnsHostName\$ObjectName" -v -getreg Policy > "$CurrentDirectory\$($ObjectName)_getreg_Policy.txt"
            certutil -config "$DnsHostName\$ObjectName" -v -cainfo > "$CurrentDirectory\$($ObjectName)_cainfo.txt"
            certutil -config "$DnsHostName\$ObjectName" -view -restrict "Disposition=20,NotAfter>=$Now" -out $DbFields csv > "$CurrentDirectory\$($ObjectName)_ValidCertificates.csv"
            certutil -config "$DnsHostName\$ObjectName" -view -restrict "Disposition=30" -out $DbFields csv > "$CurrentDirectory\$($ObjectName)_FailedRequests.csv"
            certutil -config "$DnsHostName\$ObjectName" -view -restrict "Disposition=31" -out $DbFields csv > "$CurrentDirectory\$($ObjectName)_DeniedRequests.csv"

        }

    }

}

#endregion Dump-EnrollmentServices

#region Dump-AIA

$CurrentDirectory = "$Path\KRA"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=KRA,CN=Public Key Services,CN=Services,$DsConfigDn" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName

    Write-Verbose -Message "Dumping $ObjectDn"

    certutil -v -ds $ObjectDn > "$CurrentDirectory\msPKI-PrivateKeyRevoveryAgent_$($ObjectName).txt"

}

#endregion Dump-AIA

#region Dump-OID

$CurrentDirectory = "$Path\OID"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=OID,CN=Public Key Services,CN=Services,$DsConfigDn" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName

    Write-Verbose -Message "Dumping $ObjectDn"

    certutil -v -ds $ObjectDn > "$CurrentDirectory\msPKI-Enterprise-Oid_$($ObjectName).txt"

}

#endregion Dump-OID