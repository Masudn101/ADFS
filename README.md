To install Active Directory Federation Services (ADFS) on a Windows Server, you can use both PowerShell commands and the Server Manager interface. Below is a script using PowerShell which automates the installation process:

1. **Install the ADFS role:**

```powershell
# Install the ADFS role
Install-WindowsFeature ADFS-Federation -IncludeManagementTools

# Import the ADFS module
Import-Module ADFS

# Create a new self-signed certificate for ADFS
$cert = New-SelfSignedCertificate -DnsName "adfs.contoso.com" -CertStoreLocation "Cert:\LocalMachine\My"

# Export the certificate to a PFX file (you can skip this step if you have an actual certificate)
$pwd = ConvertTo-SecureString -String "P@ssw0rd" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "C:\adfs.pfx" -Password $pwd

# Install the ADFS server
Install-AdfsFarm `
    -CertificateThumbprint $cert.Thumbprint `
    -FederationServiceDisplayName "Contoso Federation Service" `
    -FederationServiceName "adfs.contoso.com" `
    -ServiceAccountName "contoso\ADFSsvc" `
    -ServiceAccountPassword (ConvertTo-SecureString "ServiceAccountPassword" -AsPlainText -Force)

# Configure SSL binding
$sslCert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
$binding = New-Object Microsoft.Web.Administration.Binding
$binding.protocol = "https"
$binding.bindingInformation = "*:443:"
$binding.certificateStoreName = "My"
$binding.certificateHash = $sslCert.GetCertHash()
$site = Get-WebSite -Name "Default Web Site"
$site.Bindings.Add($binding)

# Start the ADFS service
Start-Service adfssrv

# Confirm ADFS is running
Get-AdfsFarmInformation
```

2. **Manual Steps:**

   - **Configure DNS**: Ensure your DNS server has an A record for your ADFS service name (e.g., adfs.contoso.com) pointing to your ADFS server's IP address.
   - **Firewall Configuration**: Ensure that your firewall allows HTTPS traffic (port 443) to your ADFS server.
   - **Certificates**: For production, use a valid SSL certificate issued by a trusted Certificate Authority (CA) instead of a self-signed certificate.

3. **Further Configuration**:
   
   - Configure the ADFS to work with your applications and trust relationships as needed.
   - Set up relying party trusts, claims provider trusts, and any additional ADFS policies required by your organization.

### Important Notes

- **Service Account**: Ensure the service account `contoso\ADFSsvc` is created and has the necessary permissions.
- **Security**: Use strong passwords and protect your certificates.
- **Custom Adjustments**: Modify the script as per your domain settings and organizational policies.

### Running the Script

1. Save the script to a `.ps1` file, e.g., `InstallADFS.ps1`.
2. Run PowerShell as Administrator.
3. Execute the script:

```powershell
Set-ExecutionPolicy Unrestricted -Scope Process
.\InstallADFS.ps1
```

This script should automate the installation and initial configuration of ADFS on your Windows Server.
