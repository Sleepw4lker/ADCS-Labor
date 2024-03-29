<#
    .SYNOPSIS
    Exports Active Directory Certificate Services Configuration Data from Active Directory
    Run this once on a Domain Controller (or any other 8.0/2012+ Machine) with AD Powershell Module installed
    Also run it locally on each Enterprise Certification Authority or use the -DumpCA parameter

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
    $DsConfigDn = ""
)

begin {

    #region Functions

    Function Remove-InvalidFileNameChars {

        [cmdletbinding()]
        param(
            [Parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [String]$Name
        )

        process {

            $invalidChars = [IO.Path]::GetInvalidFileNameChars() -join ''
            $re = "[{0}]" -f [RegEx]::Escape($invalidChars)
            return ($Name -replace $re)

        }
    }

    Function Export-CaInformation {

        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$False)]
            [ValidateNotNullOrEmpty()]
            [String]$HostName = "localhost",

            [Parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [String]$CaName,

            [Parameter(Mandatory=$True)]
            [ValidateNotNullOrEmpty()]
            [String]$Path
        )

        process {

            $Now = $((Get-Date).ToString($(Get-culture).DateTimeFormat.ShortDatePattern))
            $DbFields = "RequestID,SerialNumber,RequesterName,CommonName,CertificateTemplate,NotBefore,NotAfter"

            Write-Verbose -Message "Dumping CA Configuration from $CaName ($HostName)"

            # TestICertAdmin Connectivity first to speed up process, throw error on fail
            $CertAdmin = New-Object -ComObject CertificateAuthority.Admin.1

            Try {
                $CR_PROP_CANAME = 0x6
                $PROPTYPE_STRING = 4
                $PropIndex = 0
                $Flags = 0

                [void]($CertAdmin.GetCAProperty("$HostName\$CaName", $CR_PROP_CANAME, $PropIndex, $PROPTYPE_STRING, $Flags))
            }
            Catch {
                Write-Warning -Message "Cannot connect to $CaName ($HostName)"
                Write-Warning -Message "Configuration therefore not exported. Do this manually directly on the CA."
                return
            }

            [void](New-Item `
                -ItemType Directory `
                -Path "$Path\Enrollment Services\$($CaName)" `
                -Force `
                -ErrorAction Continue)

            # Dumping CA Configuration
            certutil -config "$HostName\$CaName" -v -getreg > "$Path\Enrollment Services\$($CaName)\$($CaName)_getreg.txt"
            certutil -config "$HostName\$CaName" -v -getreg CA > "$Path\Enrollment Services\$($CaName)\$($CaName)_getreg_CA.txt"
            certutil -config "$HostName\$CaName" -v -getreg CA\CSP > "$Path\Enrollment Services\$($CaName)\$($CaName)_getreg_CA_CSP.txt"
            certutil -config "$HostName\$CaName" -v -getreg CA\EncryptionCSP > "$Path\Enrollment Services\$($CaName)\$($CaName)_getreg_CA_EncryptionCSP.txt"
            certutil -config "$HostName\$CaName" -v -getreg Policy > "$Path\Enrollment Services\$($CaName)\$($CaName)_getreg_Policy.txt"
            certutil -config "$HostName\$CaName" -v -cainfo > "$Path\Enrollment Services\$($CaName)\$($CaName)_cainfo.txt"
            certutil -config "$HostName\$CaName" -view -restrict "Disposition=20,NotAfter>=$Now" -out $DbFields csv > "$Path\Enrollment Services\$($CaName)\$($CaName)_Certs_Valid.csv"
            certutil -config "$HostName\$CaName" -view -restrict "Disposition=30" -out $DbFields csv > "$Path\Enrollment Services\$($CaName)\$($CaName)_Certs_Failed.csv"
            certutil -config "$HostName\$CaName" -view -restrict "Disposition=31" -out $DbFields csv > "$Path\Enrollment Services\$($CaName)\$($CaName)_Certs_Denied.csv"

            # Dumping and verifying the CA Exchange Certificate
            certutil -config "$HostName\$CaName" -cainfo xchg > "$Path\Enrollment Services\$($CaName)\$($CaName)_xchg_BASE64.txt"
            certutil -dump "$Path\Enrollment Services\$($CaName)\$($CaName)_xchg_BASE64.txt" > "$Path\Enrollment Services\$($CaName)\$($CaName)_xchg_dump.txt"
            certutil -verify -urlfetch "$Path\Enrollment Services\$($CaName)\$($CaName)_xchg_BASE64.txt" > "$Path\Enrollment Services\$($CaName)\$($CaName)_xchg_verify.txt"

            Copy-Item `
                -Path "$($env:SystemRoot)\capolicy.inf" `
                -Destination "$Path\Enrollment Services\$($CaName)\$($CaName)_capolicy.inf" `
                -ErrorAction SilentlyContinue

            If ($HostName -eq "localhost") {

                # Ensuring the Script will be run with Elevation
                If (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
                    Write-Warning -Message "Please run this again with Elevation (run as Administrator) to be able to export CA Logs."
                }
                Else {

                    # Exporting the Windows Event Log will in most cases work only locally

                    $Limit = (Get-Date).AddDays(-90)
                    $EventSources = "Microsoft-Windows-CertificationAuthority","ESENT"

                    Get-EventLog -LogName Application -Source $EventSources -After $Limit -ErrorAction SilentlyContinue | 
                        Sort-Object -Property TimeGenerated -Descending |
                            Select-Object -Property EntryType, TimeGenerated, Source, EventID, Message | 
                                Export-CSV "$Path\Enrollment Services\$($CaName)\$($CaName)_EventLog-Overview.csv" -Delimiter ";" -NoTypeInfo

                    "Application","Security","System" | ForEach-Object -Process {
                        [void](Get-WmiObject -Class Win32_NTEventlogFile | Where-Object LogfileName -EQ $_).BackupEventlog(
                            "$Path\Enrollment Services\$($CaName)\$($CaName)_Log_$($_).evtx"
                            )
                    }

                    # Exporting local Firewall Rules
                    Get-NetFirewallRule | Export-Csv -Path "$Path\Enrollment Services\$($CaName)\$($CaName)_FirewallRules.csv" -Encoding UTF8 -Delimiter ";"

                    # Exporting local System Info
                    ipconfig /all > "$Path\Enrollment Services\$($CaName)\$($CaName)_ipconfig.txt"
                    msinfo32 /report "$Path\Enrollment Services\$($CaName)\$($CaName)_msinfo32.txt"
                    auditpol /get /category:* > "$Path\Enrollment Services\$($CaName)\$($CaName)_auditpol.txt"

                    "Computer","User" | ForEach-Object -Process {

                        # Avoiding ERROR: Value for 'xyz.html' option cannot be more than 127 character(s).
                        $TempFile = "$($env:TEMP)\$(Get-Random).html"
                        gpresult /scope:$($_) /H $TempFile
                        Copy-Item -Path $TempFile -Destination "$Path\Enrollment Services\$($CaName)\$($CaName)_gpresult_$($_).html"
                        Remove-Item $TempFile
                    }
                }

                $UseDs = (Get-ItemProperty `
                    -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\$ObjectName" `
                    -Name UseDS `
                    -ErrorAction Stop).UseDS

                If ($UseDs -eq 1) {

                    Get-CATemplate | Sort-Object -Property Name | Select-Object -ExpandProperty Name | Out-File `
                        -FilePath "$Path\Enrollment Services\$($CaName)_CATemplates.txt" `
                        -Encoding UTF8 `
                        -Force

                    Get-CATemplate | Foreach-Object {
                        certutil -policyserver ldap: -v -template $_.Name > "$Path\Certificate Templates\pKICertificateTemplate_$(Remove-InvalidFileNameChars -Name $($_.Name)).txt"
                    }
                }
            }
        }
    }

    #endregion Functions
}

<#
To Do:
- Implement Support for Client Operating Systems (RSAT is detected differently)
- Improve Error Handling
- Put ADCS Connectivity Test in a meaningful Function
- Merge AIA and Certification Authorities Dump
- Dump CrossCA Certificates
#>

process {

    #region Test-Prerequisites

    # Ensuring the Script will be run on a supported Operating System
    $OS = Get-WmiObject -Class Win32_OperatingSystem
    If (($OS.name -notmatch "Server") -or ([int32]$OS.BuildNumber -lt 9200)) {
        Write-Warning -Message "This Script must be run on Windows Server 2012 or newer! Aborting."
        return 
    }

    #endregion Test-Prerequisites

    [void](New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop)

    #region Detect-CaInstallation

    Try {
        $ObjectName = (Get-ItemProperty `
            -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" `
            -Name Active `
            -ErrorAction Stop).Active
    }
    Catch {
        # Nothing. We silently continue with the AD Dump.
    }

    # Exporting local Configuration Data if a CA is installed on this machine
    If ($ObjectName) {

        "Enrollment Services","Certificate Templates" | ForEach-Object -Process {

            [void](New-Item -ItemType Directory -Path "$Path\$_" -Force -ErrorAction Continue)
        }

        Write-Host "Exporting local CA Configuration Data."

        $CurrentDirectory = "$Path\Enrollment Services"
        [void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

        Export-CaInformation -CaName $ObjectName -Path $Path
    }

    #endregion Detect-CaInstallation

    #region Prepare-ADDump

    Write-Host "Exporting Active Directory PKI Configuration Data."

    # Ensuring we have required AD PowerShell Modules installed
    If ((Get-WindowsFeature RSAT-AD-PowerShell).Installed -ne $True) {
        Write-Warning -Message "Export of Active Directory Data requires AD PowerShell Modules (RSAT-AD-PowerShell) to be installed! Aborting."
        Write-Warning -Message "If you only export local data from a CA, you may safely ignore this message."
        return 
    }

    Import-Module ActiveDirectory

    If ([String]::IsNullOrEmpty($DsConfigDn)) {
        $DsConfigDn = "CN=Configuration,$($(Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain).DistinguishedName)"
    }

    $PkiDn = "CN=Public Key Services,CN=Services,$DsConfigDn"

    "AIA","CDP","Enrollment Services","Certification Authorities","Certificate Templates","KRA","OID","NTAuthCertificates" | ForEach-Object -Process {

        [void](New-Item -ItemType Directory -Path "$Path\$_" -Force -ErrorAction Continue)
    }

    #region Prepare-ADDump

    #region Dump-AIA

    $CurrentDirectory = "$Path\AIA"

    Get-ChildItem -Path "AD:CN=AIA,$PkiDn" | Foreach-Object -Process {

        $ObjectName = $_.Name
        $ObjectDn = $_.DistinguishedName
        Write-Verbose -Message "Dumping $ObjectDn"

        certutil -v -ds $ObjectDn > "$CurrentDirectory\certificationAuthority_$($ObjectName).txt"

        (Get-Acl "AD:$ObjectDn").access | Out-File `
            -FilePath "$CurrentDirectory\certificationAuthority_$($ObjectName)-access.txt" `
            -Encoding UTF8 `
            -Force

        $i = 0
        $(Get-ADObject $_ -Properties cACertificate).cACertificate | Foreach-Object -Process {

            $FileName = "$CurrentDirectory\$($ObjectName)_cACertificate_($($i))"

            # CRT Files are usually blocked by E-Mail Anti-Virus, thus only exporting in BASE64 Encoding to Text Files
            Set-Content `
                -Value "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($_))`n-----END CERTIFICATE-----" `
                -Encoding UTF8 `
                -Path "$($FileName)_BASE64.txt" `
                -Force

            certutil -dump "$($FileName)_BASE64.txt" > "$($FileName)_BASE64_dump.txt"
            certutil -verify -urlfetch "$($FileName)_BASE64.txt" > "$($FileName)_BASE64_verify.txt"
            $i++
        }
    }

    #endregion Dump-AIA

    #region Dump-CDP

    Get-ChildItem -Path "AD:CN=CDP,$PkiDn" | Foreach-Object -Process {

        $ObjectName = $_.Name

        $CurrentDirectory = "$Path\CDP\$($ObjectName)"
        [void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

        # Enumerate Sub Directories
        Get-ChildItem -Path "AD:$($_.DistinguishedName)" | Foreach-Object -Process {

            $ObjectName = $_.Name
            $ObjectDn = $_.DistinguishedName

            Write-Verbose -Message "Dumping $ObjectDn"

            certutil -v -ds $ObjectDn > "$CurrentDirectory\cRLDistributionPoint_$($ObjectName).txt"

            $Crl = $(Get-ADObject $_ -Properties certificateRevocationList).certificateRevocationList

            If ($Crl.Length -gt 1) {

                $FileName = "$CurrentDirectory\$($ObjectName)_certificateRevocationList"
                Set-Content -Value $Crl -Encoding Byte -Path "$($FileName).crl" -Force -ErrorAction SilentlyContinue

                # Dump disabled for now as this may affect Performance on larger CRLs
                #certutil -dump "$($FileName).crl" > "$($FileName)-dump.txt"
            }
            
            $DeltaCrl = $(Get-ADObject $_ -Properties deltaRevocationList).deltaRevocationList

            If ($DeltaCrl.Length -gt 1) {

                $FileName = "$CurrentDirectory\$($ObjectName)_deltaRevocationList"
                Set-Content -Value $DeltaCrl -Encoding Byte -Path "$($FileName)+.crl" -Force -ErrorAction SilentlyContinue

                # Dump disabled for now as this may affect Performance on larger CRLs
                #certutil -dump "$($FileName)+.crl" > "$($FileName)+-dump.txt"
            }
        }
    }

    #endregion Dump-CDP

    # region Dump-CertificateTemplates

    $CurrentDirectory = "$Path\Certificate Templates"

    Get-ChildItem -Path "AD:CN=Certificate Templates,$PkiDn" | Foreach-Object -Process {

        $ObjectName = $_.Name
        $ObjectDn = $_.DistinguishedName

        Write-Verbose -Message "Dumping $ObjectDn"

        certutil -policyserver ldap: -v -template $ObjectName > "$CurrentDirectory\pKICertificateTemplate_$(Remove-InvalidFileNameChars -Name $($ObjectName)).txt"
    }

    # region Dump-CertificateTemplates

    #region Dump-CertificationAuthorities

    $CurrentDirectory = "$Path\Certification Authorities"

    Get-ChildItem -Path "AD:CN=Certification Authorities,$PkiDn" | Foreach-Object -Process {

        $ObjectName = $_.Name
        $ObjectDn = $_.DistinguishedName
        Write-Verbose -Message "Dumping $ObjectDn"

        certutil -v -ds $ObjectDn > "$CurrentDirectory\certificationAuthority_$($ObjectName).txt"

        $i = 0
        $(Get-ADObject $_ -Properties cACertificate).cACertificate | Foreach-Object -Process {

            $FileName = "$CurrentDirectory\$($ObjectName)_cACertificate_($($i))"
            
            # CRT Files are usually blocked by E-Mail Anti-Virus, thus only exporting in BASE64 Encoding to Text Files
            Set-Content `
                -Value "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($_) -replace '.{64}', "`$&`n")`n-----END CERTIFICATE-----" `
                -Encoding UTF8 `
                -Path "$($FileName)_BASE64.txt" `
                -Force

            certutil -dump "$($FileName)_BASE64.txt" > "$($FileName)_BASE64_dump.txt"
            certutil -verify -urlfetch "$($FileName)_BASE64.txt" > "$($FileName)_BASE64_verify.txt"
            $i++
        }
    }

    #endregion Dump-CertificationAuthorities

    #region Dump-EnrollmentServices

    $CurrentDirectory = "$Path\Enrollment Services"

    Get-ChildItem -Path "AD:CN=Enrollment Services,$PkiDn" | Foreach-Object -Process {

        $ObjectName = $_.Name
        $ObjectDn = $_.DistinguishedName

        Write-Verbose -Message "Dumping $ObjectDn"

        certutil -v -ds $ObjectDn > "$CurrentDirectory\pKIEnrollmentService_$($ObjectName).txt"

        $DnsHostName = $(Get-ADObject $_ -Properties dNSHostName).dNSHostName

        # Dumping which Certificate Templates are bound to each CA
        (Get-ADObject $_ -Properties certificateTemplates).certificateTemplates | Sort-Object | Out-File `
                -FilePath "$CurrentDirectory\$($ObjectName)_CATemplates.txt" `
                -Encoding UTF8 `
                -Force

        If ($DumpCA.IsPresent) { Export-CaInformation -HostName $DnsHostName -CaName $ObjectName -Path $Path }
    }

    #endregion Dump-EnrollmentServices

    #region Dump-AIA

    $CurrentDirectory = "$Path\KRA"

    Get-ChildItem -Path "AD:CN=KRA,$PkiDn" | Foreach-Object -Process {

        $ObjectName = $_.Name
        $ObjectDn = $_.DistinguishedName

        Write-Verbose -Message "Dumping $ObjectDn"

        certutil -v -ds $ObjectDn > "$CurrentDirectory\msPKI-PrivateKeyRevoveryAgent_$($ObjectName).txt"
    }

    #endregion Dump-AIA

    #region Dump-OID

    $CurrentDirectory = "$Path\OID"

    Get-ChildItem -Path "AD:CN=OID,$PkiDn" | Foreach-Object -Process {

        $ObjectName = $_.Name
        $ObjectDn = $_.DistinguishedName

        Write-Verbose -Message "Dumping $ObjectDn"

        certutil -v -ds $ObjectDn > "$CurrentDirectory\msPKI-Enterprise-Oid_$($ObjectName).txt"
    }

    #endregion Dump-OID

    # region Dump-NTAuthCertificates

    $CurrentDirectory = "$Path\NTAuthCertificates"

    $i = 0
    $(Get-ADObject "CN=NTAuthCertificates,$PkiDn" -Properties cACertificate).cACertificate | Foreach-Object -Process {

        $FileName = "$CurrentDirectory\cACertificate_($($i))"
        
        # CRT Files are usually blocked by E-Mail Anti-Virus, thus only exporting in BASE64 Encoding to Text Files
        Set-Content `
            -Value "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($_) -replace '.{64}', "`$&`n")`n-----END CERTIFICATE-----" `
            -Encoding UTF8 `
            -Path "$($FileName)_BASE64.txt" `
            -Force
        
        certutil -dump "$($FileName)_BASE64.txt" > "$($FileName)_BASE64_dump.txt"
        certutil -verify -urlfetch "$($FileName)_BASE64.txt" > "$($FileName)_BASE64_verify.txt"
        $i++
    }
} 

end {}