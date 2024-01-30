# Define ntfy server details
$ntfyURI = "YOUR SERVER ADDRESS HERE"
$ntfyToken = "YOUR TOKEN HERE"
#I worked on this longer than expected

# Initialize variables to store previous login information
$previousLogonUser = $null
$previousIpAddress = $null
$previousWorkstation = $null
$previousLogonProcess = $null

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

# Calculate the time 30 minutes ago
$StartTime = (Get-Date).AddMinutes(-300)

# Event log filter for RDP logon events within the last 30 minutes
$Filter = @{
    LogName = 'Security'
    Id = 4624  # Logon success event ID
    StartTime = $StartTime
}

# Start monitoring event log
Get-WinEvent -FilterHashtable $Filter | ForEach-Object {
    $Event = $_
    $Properties = $Event.Properties

    # Check if the logon type corresponds to a remote desktop logon (Type 10)
    $LogonType = $Properties[8].Value  # Logon Type
    if ($LogonType -ne 10) {
        return  # Skip if not a remote desktop logon
    }

    # Extract user, IP address, workstation name, and logon process name from event properties
    $LogonUser = $Properties[5].Value  # Account Name
    $IpAddress = $Properties[18].Value  # Source Network Address
    $Workstation = $Properties[13].Value  # Workstation Name
    $LogonProcess = $Properties[10].Value  # Logon Process Name

    # Check if the current login information is the same as the previous one
    if ($LogonUser -eq $previousLogonUser -and $IpAddress -eq $previousIpAddress -and $Workstation -eq $previousWorkstation -and $LogonProcess -eq $previousLogonProcess) {
        return  # Skip if the current login is the same as the previous one
    }

    # Format the message
    if ($LogonUser -and $IpAddress -and $Workstation -and $LogonProcess) {
        $Message = "RDP login - User: $LogonUser, IP Address: $IpAddress, Workstation: $Workstation, Logon Process: $LogonProcess"
    }
    else {
        $Message = "RDP login - User, IP Address, Workstation, or Logon Process information not available"
    }

    # Send message to ntfy server
    Send-NtfyMessage -Message $Message

    # Update previous login information
    $previousLogonUser = $LogonUser
    $previousIpAddress = $IpAddress
    $previousWorkstation = $Workstation
    $previousLogonProcess = $LogonProcess
}
