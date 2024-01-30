# Define ntfy server details
$ntfyURI = "HTTPS://YOURSERVERADDRES/TOPICHERE"
$ntfyToken = "YOUR TOKEN HERE"

# Function to send message to ntfy server
function Send-NtfyMessage {
    param (
        [string]$Message
    )

    $Headers = @{
        "Authorization" = "Bearer $ntfyToken"
    }
    $Body = @{
        "message" = $Message
    } | ConvertTo-Json  # Convert message to JSON format

    try {
        Invoke-RestMethod -Uri $ntfyURI -Method Post -Headers $Headers -Body $Body -ErrorAction Stop
    } catch {
        Write-Host "Error sending notification: $_"
    }
}

# Function to check if port 3389 is connected
function Check-Port3389Connection {
    $Port3389Connection = netstat -an | Select-String ":3389"
    if ($Port3389Connection) {
        return $true
    } else {
        return $false
    }
}

# Function to monitor the latest Event ID 25 or Event ID 4624 and check port 3389 connection
function Monitor-LatestLogonAndPort3389 {
    # Check for the latest Event ID 25
    $Event25 = Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" -FilterXPath "*[System[(EventID=25)]]" -MaxEvents 1
    if ($Event25) {
        $User25 = $Event25.Properties.Value[4]
        $IPAddress25 = $Event25.Properties.Value[5]
        $DateTime25 = $Event25.TimeCreated
        $Message = "Latest Event ID 25 - Date and Time: $($DateTime25.ToUniversalTime().ToString('dd-MM-yyyy HH:mm:ss')), User: $User25, IP Address: $IPAddress25 "
    }

    # Check for the latest Event ID 4624 with logon type 7 or 10
    $Event4624 = Get-WinEvent -LogName "Security" -FilterXPath "*[System[(EventID=4624)]]" | Where-Object { $_.Properties[8].Value -in @(7, 10) } | Sort-Object TimeCreated -Descending | Select-Object -First 1
    if ($Event4624) {
        $User4624 = $Event4624.Properties[5].Value
        $IPAddress4624 = $Event4624.Properties[18].Value
        $DateTime4624 = $Event4624.TimeCreated
        $LogonType4624 = $Event4624.Properties[8].Value
        $Message = "Latest Event ID 4624 - Date and Time: $($DateTime4624.ToUniversalTime().ToString('dd-MM-yyyy HH:mm:ss')), User: $User4624, IP Address: $IPAddress4624, Logon Type: $LogonType4624 "
    }

    # Check if port 3389 is connected
    $Port3389Status = Check-Port3389Connection
    if ($Port3389Status) {
        $Message += "Port 3389 is connected."
    }

    # Send message to ntfy server if there is a message to send
    if ($Message) {
        Send-NtfyMessage -Message $Message
    } else {
        Send-NtfyMessage -Message "No recent login events found."
    }
}

# Monitor the latest Event ID 25 or Event ID 4624 and port 3389 connection
Monitor-LatestLogonAndPort3389
