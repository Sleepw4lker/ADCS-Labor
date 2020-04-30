$Now = $((Get-Date).ToString($(Get-culture).DateTimeFormat.ShortDatePattern))

# Dumping CA Configuration
certutil -v -getreg CA > "$($env:COMPUTERNAME)_getreg_CA.txt"
certutil -v -getreg CA\CSP > "$($env:COMPUTERNAME)_getreg_CA_CSP.txt"
certutil -v -getreg Policy > "$($env:COMPUTERNAME)_getreg_Policy.txt"
certutil -v -cainfo > "$($env:COMPUTERNAME)_cainfo.txt"
certutil -view -restrict "Disposition=20,NotAfter>=$Now" -out "RequestID,SerialNumber,RequesterName,CommonName,CertificateTemplate,NotBefore,NotAfter" csv > "$($env:COMPUTERNAME)_ValidCertificates.csv"
certutil -view -restrict "Disposition=30" -out "RequestID,Request.StatusCode,RequesterName,CommonName,CertificateTemplate,NotBefore,NotAfter" csv > "$($env:COMPUTERNAME)_FailedRequests.csv"
certutil -view -restrict "Disposition=31" -out "RequestID,Request.StatusCode,RequesterName,CommonName,CertificateTemplate,NotBefore,NotAfter" csv > "$($env:COMPUTERNAME)_DeniedRequests.csv"