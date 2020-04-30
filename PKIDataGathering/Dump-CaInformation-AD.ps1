[cmdletbinding()]
param (
    [Parameter(Mandatory=$False)]
    [Switch]
    $DumpCA = $False,

    [Parameter(Mandatory=$False)]
    [String]
    $Path = $(Split-Path -Path $MyInvocation.MyCommand.Definition -Parent)
)

# Run this once on a Domain Controller (or any other 8.0/2012+ Machine) with AD Powershell Module installed
Import-Module ActiveDirectory
$DsConfigDN = "CN=Configuration,$($(Get-ADForest | Select-Object -ExpandProperty RootDomain | Get-ADDomain).DistinguishedName)"

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

[void](New-Item -ItemType Directory -Path $Path -Force -ErrorAction Stop)

$CurrentDirectory = "$Path\AIA"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=AIA,CN=Public Key Services,CN=Services,$DsConfigDN" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName
    Write-Verbose -Message "Dumping $ObjectDn"

    # Windows 2012/R2 do not seem to support specifying further Arguments
    certutil -v -ds $ObjectDn > "$CurrentDirectory\certificationAuthority_$($ObjectName).txt"

    $i = 0
    $(Get-ADObject $_ -Properties cACertificate).cACertificate | Foreach-Object {
        $FileName = "$CurrentDirectory\$($ObjectName)_cACertificate_($($i))"
        # CRT Files are usually blocked by E-Mail Anti-Virus, thus only exporting in BASE64 Encoding to Text Files
        Set-Content -value "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($_))`n-----END CERTIFICATE-----" -Encoding UTF8 -path "$($FileName)_BASE64.txt" -Force
        certutil -dump "$($FileName)_BASE64.txt" > "$($FileName)_BASE64_dump.txt"
        $i++
    }

}

Get-ChildItem "AD:CN=CDP,CN=Public Key Services,CN=Services,$DsConfigDN" | Foreach-Object -Process {

    $ObjectName = $_.Name

    # Not elegant, should rethink this
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
            Set-Content -value $Crl -Encoding Byte -path "$($FileName).crl" -Force -ErrorAction SilentlyContinue
        }
        
        $DeltaCrl = $(Get-ADObject $_ -Properties deltaRevocationList).deltaRevocationList
        If ($DeltaCrl.Length -gt 1) {
            $FileName = "$CurrentDirectory\$($ObjectName)_deltaRevocationList"
            Set-Content -value $DeltaCrl -Encoding Byte -path "$($FileName)+.crl" -Force -ErrorAction SilentlyContinue
        }

    }

}


$CurrentDirectory = "$Path\Certificate Templates"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=Certificate Templates,CN=Public Key Services,CN=Services,$DsConfigDN" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName
    Write-Verbose -Message "Dumping $ObjectDn"

    $TemplateName = Remove-InvalidFileNameChars $($ObjectName)
    certutil -v -template $TemplateName > "$CurrentDirectory\pKICertificateTemplate_$($TemplateName).txt"

}

# Exactly the same as AIA above, should pack it into a function

$CurrentDirectory = "$Path\Certification Authorities"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=Certification Authorities,CN=Public Key Services,CN=Services,$DsConfigDN" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName
    Write-Verbose -Message "Dumping $ObjectDn"

    # Windows 2012/R2 do not seem to support specifying further Arguments
    certutil -v -ds $ObjectDn > "$CurrentDirectory\certificationAuthority_$($ObjectName).txt"

    $i = 0
    $(Get-ADObject $_ -Properties cACertificate).cACertificate | Foreach-Object {
        $FileName = "$CurrentDirectory\$($ObjectName)_cACertificate_($($i))"
        # CRT Files are usually blocked by E-Mail Anti-Virus, thus only exporting in BASE64 Encoding to Text Files
        #Set-Content -value $_ -Encoding Byte -path "$($FileName).crt" -Force
        Set-Content -value "-----BEGIN CERTIFICATE-----`n$([Convert]::ToBase64String($_))`n-----END CERTIFICATE-----" -Encoding UTF8 -path "$($FileName)_BASE64.txt" -Force
        certutil -dump "$($FileName)_BASE64.txt" > "$($FileName)_BASE64_dump.txt"
        $i++
    }

}



$CurrentDirectory = "$Path\Enrollment Services"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=Enrollment Services,CN=Public Key Services,CN=Services,$DsConfigDN" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName

    Write-Verbose -Message "Dumping $ObjectDn"

    # Windows 2012/R2 do not seem to support specifying further Arguments
    certutil -v -ds $ObjectDn > "$CurrentDirectory\pKIEnrollmentService_$($ObjectName).txt"

    $DnsHostName = $(Get-ADObject $_ -Properties dNSHostName).dNSHostName

    # Dumping which Certificate Templates are bound to each CA
    (Get-ADObject $_ -Properties certificateTemplates).certificateTemplates | Out-File -FilePath "$CurrentDirectory\$($ObjectName)_CATemplates.txt" -Encoding String -Force


    # Requires Remote Connectivity and "read" Permission on CA
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



$CurrentDirectory = "$Path\KRA"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=KRA,CN=Public Key Services,CN=Services,$DsConfigDN" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName

    Write-Verbose -Message "Dumping $ObjectDn"

    certutil -v -ds $ObjectDn > "$CurrentDirectory\msPKI-PrivateKeyRevoveryAgent_$($ObjectName).txt"

}



$CurrentDirectory = "$Path\OID"
[void](New-Item -ItemType Directory -Path $CurrentDirectory -Force -ErrorAction Continue)

Get-ChildItem "AD:CN=OID,CN=Public Key Services,CN=Services,$DsConfigDN" | Foreach-Object -Process {

    $ObjectName = $_.Name
    $ObjectDn = $_.DistinguishedName

    Write-Verbose -Message "Dumping $ObjectDn"

    certutil -v -ds $ObjectDn > "$CurrentDirectory\msPKI-Enterprise-Oid_$($ObjectName).txt"

}