$client = New-Object System.Net.Sockets.TcpClient
$client.BeginConnect("50.16.16.211", 443, $null, $null) | Out-Null
Start-Sleep -Seconds 10