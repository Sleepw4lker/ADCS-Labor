# NDESmanualInstallation

Some files that are helpful when installing NDES without Enterprise Administrator Permission (which isn't officially supported, but may be the only way in restrictive Active Directory Environments).

The sample files are from a Windows Server 2019 Installation using the Built-In Application Pool Identity. It is possible to change all Settings after the initial Setup.

## How to manually install NDES without Enterprise Administrator Permissions

The Steps are:

### Install prerequisites

```powershell
Add-WindowsFeature Web-Server -IncludeManagementTools
Add-WindowsFeature ADCS-Device-Enrollment -IncludeManagementTools
```

This will ensure the required binary files are present under C:\Windows\System32\certsrv\mscep.

### Replace this file with the one from the Repo

C:\Windows\System32\inetsrv\Config\applicationHost.config

The Original Version is included as applicationHost.config.original so that you can compare them if desired.

### Import Registry

- MSCEP.reg sets the default Registry Values for the NDES Service. It contains the CA Config which must be adapted to your Environment. Further Changes as needed.
- ConfigurationStatus.reg will tell Server Manager that the Role has been configured.

### Request RA Certificates

- Create Custom Certificate Templates based on "CEP Encryption" and "Enrollment Agent (Computer)", and issue the to the Computer Certificate Store.
- NDESAppPoolKeyPermissions.ps1 will set Read Permissions on the Certificates Private Keys for the SCEP IIS Application Pool.

### Reload config

```cmd
iisreset
```

### Update Target CA Configuration
```cmd
certutil -setreg CA\SubjectTemplate +UnstructuredName
certutil -setreg CA\SubjectTemplate +UnstructuredAddress
certutil -setreg CA\SubjectTemplate +DeviceSerialNumber
net stop certsvc
net start cetrsvc
```