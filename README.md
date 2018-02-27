# Azure Monitoring

## Azure Windows VM monitoring with WinRM
Windows에서 제공되는 [Performance Monitor]는 Windows에 대한 다양한 성능 metric 및 로그를 실시간으로 제공합니다.

이러한 Windows OS단의 매트릭들은 Microsoft의 [Web Services for Management(WS-Management)프로토콜]을 통해 remote에서 모니터링 할 수 있습니다.

아래는 WinRM(Windows Remote Management) scripting 객체를 이용하여 Azure상의 Windows Virtual Machine의 Guest OS단 주요 성능 metric들을 monitoring하는 방법을 기술합니다.

### Setting up WinRM on Azure Windows VM with PowerShell
1. Create a Key Vault
       New-AzureRmKeyVault -VaultName mykeyvault -ResourceGroupName myResourceGroup -Location "koreacentral" -EnabledForDeployment -EnabledForTemplateDeployment

2. Create a self-signed certificate
        $certificateName = "mytestcertificate"
        $thumbprint = (New-SelfSignedCertificate -DnsName $certificateName -CertStoreLocation Cert:\CurrentUser\My -KeySpec KeyExchange).Thumbprint
        $cert = (Get-ChildItem -Path cert:\CurrentUser\My\$thumbprint)
        $password = Read-Host -Prompt "Please enter the certificate password." -AsSecureString
        Export-PfxCertificate -Cert $cert -FilePath ".\$certificateName.pfx" -Password $password

3. Upload your self-signed certificate to the key vault
        $fileName = "./mytestcertificate.pfx"
        $fileContentBytes = Get-Content $fileName -Encoding Byte
        $fileContentEncoded = [System.Convert]::ToBase64String($fileContentBytes)

        $jsonObject = @"
        {
          "data": "$filecontentencoded",
          "dataType" :"pfx",
          "password": ""
        }
        "@

        $jsonObjectBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonObject)
        $jsonEncoded = [System.Convert]::ToBase64String($jsonObjectBytes)

        $secret = ConvertTo-SecureString -String $jsonEncoded -AsPlainText –Force
        Set-AzureKeyVaultSecret -VaultName "mykeyvault" -Name "mysecret" -SecretValue $secret

        $secretURL = (Get-AzureKeyVaultSecret -VaultName hyukkeyvault -Name hyuksecret).Id

4. Create Windows VM with reference to your self-signed certificates URL using [201-vm-winrm-keyvault-windows] template

5. Connect to the VM using RDP and check if WinRM service is running using powershell command and enable PowerShell remoting as below.
        > Get-Service WinRM
        Status   Name               DisplayName
        ------   ----               -----------
        Running  WinRM              Windows Remote Management (WS-Manag...

        > Enable-PSRemoting -Force

6. On monitoring client machine, check if WinRM connection is working using Windows VM IP address.
        Enter-PSSession -ConnectionUri https://52.166.74.151:5986 -Credential $cred -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck) -Authentication Negotiate


-----------------------------------------------
아래는 Azure Keyvault를 이용하지 않고 기존에 생성된 Windows VM에 WinRM을 설치하는 방법입니다.

1. 해당 VM의 NSG의 incoming rule에 5986 port를 허용하도록 추가합니다.
2. 해당 VM Guest OS의 Windows 방화벽 설정에서 5986 port에 대해 incoming 허용 rule을 추가합니다.
3. VM Guest OS내에서 Self-Signed 인증서를 생성합니다.

        > New-SelfSignedCertificate -DnsName mytestdns -CertStoreLocation Cert:\LocalMachine\My

        PSParentPath: Microsoft.PowerShell.Security\Certificate::LocalMachine\My

        Thumbprint                          Subject
        ----------                          -------
        E6D1D3A44806C9EEF37514C14C1E64BEF50B3F36  CN=mytestdns

4. 5986 port로 HTTPS 요청을 listen 하도록 명령
        C:\Windows\System32>winrm create winrm/config/Listener?Address=*+Transport=HTTPS @{Hostname="hyuktestdns"; CertificateThumbprint="E6D1D3A44806C9EEF37514C14C1E64BEF50B3F36"}
        ResourceCreated
            Address = http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous
            ReferenceParameters
                ResourceURI = http://schemas.microsoft.com/wbem/wsman/1/config/listener
                SelectorSet
                    Selector: Address = *, Transport = HTTPS


### Getting Windows performance metrics from Azure Windows VM using WinRM
        $serverName = "xxx.xxx.xxx.xxx"

        # Get Available Memory of the VM
        > $cred = Get-Credential
        > $ServerSession = New-PSSession -ConnectionUri https://"$serverName":5986 -Credential $cred -SessionOption (New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck) -Authentication Negotiate
        > [decimal]$AvailMemory = "{0:n2}" -f (Invoke-Command -Session $ServerSession -ScriptBlock {Get-Counter -counter "\Memory\Available MBytes" | Select-Object -ExpandProperty countersamples} -ErrorAction SilentlyContinue).CookedValue
        > $AvailMemory
        2551.00

## Azure Linux VM monitoring

Azure Host단의 CPU, Disk, Network관련 metric들은 Azure Monitoring Test API를 이용하여 실시간으로 query할 수 있습니다. [Azure Linux Diagnostic Extension]을 설치하면 Memory관련 metric들을 포함한 Azure Azure Guest OS단의 metric들을 Azure Storage에 수집할 수 있습니다.

또한 Azure marketplace에서 VM monitoring을 위한 다양한 3rd party extension들을 찾을 수 있습니다. (https://docs.microsoft.com/en-us/azure/monitoring-and-diagnostics/monitoring-partners 참조)


Ref)
https://docs.microsoft.com/en-us/azure/virtual-machines/windows/winrm
http://www.techdiction.com/2016/02/11/configuring-winrm-over-https-to-enable-powershell-remoting/
https://azure.microsoft.com/en-us/resources/templates/201-vm-winrm-windows/
https://github.com/Azure/azure-linux-extensions/blob/master/Diagnostic/virtual-machines-linux-diagnostic-extension-v3.md
https://docs.microsoft.com/en-us/azure/monitoring-and-diagnostics/monitoring-rest-api-walkthrough

[Performance Monitor]: https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc749115%28v%3dws.10%29
[Web Services for Management(WS-Management)프로토콜]: https://msdn.microsoft.com/ko-kr/library/aa384426(v=vs.85).aspx
[201-vm-winrm-keyvault-windows]: https://azure.microsoft.com/documentation/templates/201-vm-winrm-keyvault-windows
[Azure Linux Diagnostic Extension]: https://docs.microsoft.com/en-us/azure/virtual-machines/linux/diagnostic-extension
