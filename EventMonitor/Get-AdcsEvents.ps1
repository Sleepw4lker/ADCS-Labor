param (
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $From = "$($env:ComputerName)@domain.tld",
    
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String[]]
    $To = ("admin1@domain.tld", "admin2@domain.tld"),
    
    [Parameter(Mandatory=$False)]
    [ValidateNotNullOrEmpty()]
    [String]
    $SmartHost = "my.smart.host",

    [Parameter(Mandatory=$False)]
    [ValidateRange(1,10)]
    [Int]
    $Retries = 5,
    
    [Parameter(Mandatory=$False)]
    [ValidateRange(1,1440)]
    [Int]
    $Minutes = 10
)

begin {

$Head = @'
<style type="text/css">
<!-

table {
  border-collapse: collapse;
  border: 1px solid black;
}

table th, td {
  border: 1px solid black;
}
->
</style>
'@

}

process {

    $StartTime = (Get-Date).AddMinutes(-$Minutes)
    $HostDisplayName = (Get-WmiObject Win32_ComputerSystem).DNSHostName

    $Events = @()

    If (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration") {

        $CaName = $(Get-ItemPropertyValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration" -Name "Active")
        $HostDisplayName = "$HostDisplayName ($CaName)"

        $Events += Get-WinEvent -FilterHashtable @{
            Logname='Application'
            ProviderName=@('Microsoft-Windows-CertificationAuthority')
            Id=@("26","15","38","46","55","60","65","67","74","95","130")   
            StartTime=($StartTime)
        }, @{
            Logname='Application'
            ProviderName=@('TameMyCerts')
            Id=@("6","8","10")
            StartTime=($StartTime)
        } -ErrorAction SilentlyContinue | Sort-Object -Property TimeCreated -Descending
    }

    If (Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Services\OcspSvc\Responder") {

        $Events += Get-WinEvent -FilterHashtable @{
            Logname='Application'
            ProviderName=@('Microsoft-Windows-OnlineResponder')
            Id=@("20","21","22","23","25","26","27","29","33","34","35")
            StartTime=($StartTime)
        }, @{
            Logname='Application'
            ProviderName=@('Microsoft-Windows-OnlineResponderRevocationProvider')
            Id=@("16","17","18")
            StartTime=($StartTime)
        },@{
            Logname='Application'
            ProviderName=@('Microsoft-Windows-OnlineResponderWebProxy')
            Id=@("17","21")
            StartTime=($StartTime)
        } -ErrorAction SilentlyContinue | Sort-Object -Property TimeCreated -Descending
    }

    If (Test-Path -Path "HKLM:\SOFTWARE\Microsoft\Cryptography\MSCEP") {

        $Events += Get-WinEvent -FilterHashtable @{
            Logname='Application'
            ProviderName=@('Microsoft-Windows-NetworkDeviceEnrollmentService')
            Id=@("2","4","8","9","10","34","35","44","49","51")
            StartTime=($StartTime)
        } -ErrorAction SilentlyContinue | Sort-Object -Property TimeCreated -Descending
    }

    If ($Events) {

        # Send Notifications for each distinct Event Id
        $Events.Id | Sort-Object | Get-Unique | ForEach-Object -Process {

            $EventId = $_
            $PartialEvents = $Events | Where-Object { $_.Id -eq $EventId }
            $EventSource = ($PartialEvents | Select-Object -First 1).ProviderName

            $Subject = "PKI Event Monitor $HostDisplayName EventID $EventId from Source $EventSource"
         
			# Build HTML Table out of the identified Events
            $Body = $PartialEvents | Select-Object -Property TimeCreated,Message | ConvertTo-HTML -Fragment
			
			# Convert Array to one String
            $Body = (ConvertTo-HTML -Body $Body -Head $Head) -join ""

            # Logic to retry on failure
            For ($i = 1; $i -le $Retries; $i++) {

                Try {
            
                    Send-MailMessage `
                        -SmtpServer $SmartHost `
                        -From $From `
                        -To $To `
                        -Subject $Subject `
                        -Body $Body `
                        -BodyAsHtml `
                        -Priority High `
                        -ErrorAction Stop

                    # Quit the loop when we're done
                    return
                }
                Catch {
                    Write-Error -Message $_.Exception.Message
                }

                # Only if it did not work the first time
                Start-Sleep -Seconds 10 
            }
        }
    }
}

end {}