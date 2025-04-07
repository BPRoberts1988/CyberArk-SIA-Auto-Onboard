# Universal Objects (Global Variables)
$identityuser = {"Insert Username Here"}
$usersecret = {"Insert Password Here"}
$domain = {"Enter Domain Here"} # Used for FQDN resolution in WORKGROUP computers.

# Global Safe Name
$safeName = {"Name of desired safe."} # Safe must exist prior to running script. 

# Declare empty global variables
$secretId = ""  # Will be assigned later
$hostname = ""  # Will be assigned later
$adminName = "" # Will be assigned later
$newPassword = "" # Will be assigned later

# Function to Log Errors to a File
function logError {
    param (
        [string]$errorMessage
    )

    $logFile = {"C:\Path\To\File"}
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp - $errorMessage"

    try {
        if (-not (Test-Path $logFile)) {
            New-Item -Path $logFile -ItemType File -Force | Out-Null
        }

        Add-Content -Path $logFile -Value $logMessage
    } catch {
        Write-Host "Error writing to log file: $($_.Exception.Message)"
    }
}


# Function to Authenticate and Get an Access Token
function autoAuth {
    Write-Host "Attempting authentication with identity service..."

    $headers = @{
        'Content-Type' = 'application/x-www-form-urlencoded'
    }

    # Form-encoded body
    $body = "grant_type=client_credentials&client_id=$identityuser&client_secret=$usersecret"

    try {
        $response = Invoke-RestMethod -Uri "{"Identity URI"}/oauth2/platformtoken" -Method POST -Headers $headers -Body $body -ErrorAction Stop
    } catch {
        logError "Error during authentication: $($_.Exception.Message)"
        Write-Host "Authentication failed. Error: $($_.Exception.Message)"
        return $null
    }

    if ($response -and $response.access_token) {
        Write-Host "Authentication successful. Access token received."
        return $response.access_token
    } else {
        Write-Host "Authentication failed. No access token received."
        logError "Authentication failed. No access token received."
        return $null
    }
}

# Function to Get the Existing Account
function getExistingAccount {
    param (
        [string]$token
    )

    Write-Host "Searching for existing account in Safe: $safeName..."

    $url = "https://{"Privilege Cloud URI"}/PasswordVault/API/Accounts?Safe=$safeName"
    $headers = @{
        'Authorization' = "Bearer $token"
    }

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
    } catch {
        logError "Failed to retrieve existing account. Error: $($_.Exception.Message)"
        Write-Host "Failed to retrieve existing account. Error: $($_.Exception.Message)"
        return $null
    }

    if ($response -and $response.value) {
        foreach ($account in $response.value) {
            if ($account.address -eq $hostname -and $account.userName -match "Administrator") {
                Write-Host "Found existing account with ID: $($account.id)"
                return $account.id
            }
        }
    }

    Write-Host "No existing account found for $hostname."
    return $null
}

# Function to Onboard a New User Account
function userOnboard {
    param (
        [string]$token,
        [string]$newPassword,  # Accepting new password as a parameter
        [string]$adminName     # Accepting admin username as a parameter
    )

    Write-Host "Onboarding new user account for administrator: $adminName on host: $hostname"

    $url = "https://{"Privilege Cloud URI"}/PasswordVault/API/Accounts/"

    $payload = @{
        "name"       = "$hostname-$adminName"
        "address"    = "$hostname"  # Combine hostname and domain for FQDN
        "userName"   = $adminName
        "platformId" = "WinServerLocal"
        "SafeName"   = $safeName
        "secret"     = $newPassword  # Using the new password generated in passwordReset
        "secretType" = "password"
    } | ConvertTo-Json

    $headers = @{
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $token"
    }

    Write-Host "Sending request to onboard user account..."
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Post -Body $payload -ErrorAction Stop
    } catch {
        logError "Error onboarding account. Response: $($_.Exception.Message)"
        Write-Host "Error onboarding account. Response: $($_.Exception.Message)"
        return $null
    }

    if ($response -and $response.id) {
        Write-Output "Account onboarded successfully. ID: $($response.id)"
        return $response.id
    } else {
        Write-Host "Error onboarding account. Response: $response"
        logError "Error onboarding account: $response"
        return $null
    }
}

# Function to Reset the Administrator's Password
function passwordReset {
    Write-Host "Searching for the Administrator account..."
    $adminAccount = Get-WmiObject Win32_UserAccount | Where-Object { $_.SID -match '-500$' }

    if ($adminAccount) {
        Write-Host "Administrator account found: $($adminAccount.Name)"

        # Generate a secure random password
        Write-Host "Generating a new secure password..."
        $newPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 16 | ForEach-Object {[char]$_})
        
        # Reset the administrator password
        Write-Host "Resetting the administrator password..."
        try {
            $adminUser = [ADSI]"WinNT://$env:COMPUTERNAME/$($adminAccount.Name),user"
            $adminUser.SetPassword($newPassword)
        } catch {
            logError "Failed to reset administrator password. Error: $($_.Exception.Message)"
            Write-Host "Failed to reset administrator password. Error: $($_.Exception.Message)"
            return $null
        }

        # Output results
        Write-Output "Password for $($adminAccount.Name) has been reset."
        
        return @{
            NewPassword = $newPassword  # Return the new password (plaintext)
            AdminName   = $adminAccount.Name  # Admin username
        }
    } else {
        Write-Host "No SID 500 account found on this machine."
        logError "No SID 500 account found on this machine."
        Write-Output "No Administrator account found."
        return $null
    }
}

# Function to Create Strong Account
function strongAccount {
    param (
        [string]$token
    )

    Write-Host "Preparing request to create strong account..."

    $headers = @{
        "Content-Type" = "application/json"
        "Authorization" = "Bearer $token"
    }

    $payload = @{
        "is_active" = "true"
        "secret" = @{
            "tenant_encrypted" = "false"
            "secret_data" = @{
                "safe" = $safeName
                "account_name" = "$hostname-$adminName"
            }
        }
        "secret_name" = "$hostname-$adminName"
        "secret_type" = "PCloudAccount"
        "secret_details" = @{
            "account_domain" = $domain
        }
    }

    Write-Host "Sending request to create a strong account..."
    try {
        $response = Invoke-RestMethod -Uri "https://{"SIA URI"}/secrets/public/v1" -Method POST -Headers $headers -Body ($payload | ConvertTo-Json -Depth 99)
    } catch {
        logError "Error creating strong account. Error: $($_.Exception.Message)"
        Write-Host "Error creating strong account. Error: $($_.Exception.Message)"
        return $null
    }

    Write-Host "Response received for strong account creation: $($response | ConvertTo-Json)"

    # Extract secret_id from response and return it
    if ($response -and $response.secret_id) {
        $secretId = $response.secret_id
        Write-Host "Strong account created successfully. Secret ID: $secretId"
        return $secretId
    } else {
        Write-Host "Error creating strong account. No secret_id found."
        logError "Error creating strong account. No secret_id found."
        return $null
    }
}

function Invoke-CyberArkTargetSet {
    param (
        [string]$token,
        [string]$secretId,
        [string]$hostname
    )

    $url = "https://{"SIA URI"}/targetsets/bulk"
    $headers = @{ "Content-Type" = "application/json"; "Authorization" = "Bearer $token" }

    $bodyObject = [PSCustomObject]@{ 
        target_sets_mapping = @(
            [PSCustomObject]@{
                strong_account_id = $secretId
                target_sets = @(
                    [PSCustomObject]@{
                        name = $hostname
                        secret_id = $secretId
                        type = "Target"
                    }
                )
            }
        )
    }

    # Convert to JSON with a sufficient depth
    $body = $bodyObject | ConvertTo-Json -Depth 99

    Write-Host "Generated JSON Body: $body"

    try {
        Write-Host "Sending request to create target set..."
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Body $body -Method Post -ErrorAction Stop
        Write-Host "Response received: $($response | ConvertTo-Json)"
        return $response | ConvertTo-Json
    } catch {
        logError "Failed to add target set. Error: $($_.Exception.Message)"
        Write-Host "Failed to add target set. Error: $($_.Exception.Message)"
        return $null
    }
}

function scriptExecute {
    Write-Host "Starting script execution..."

    # Assign the hostname here before doing anything else
    $hostname = "$env:COMPUTERNAME.$domain"
    Write-Host "Detected hostname: $hostname"

    try {
        # Authenticate and get token
        $token = autoAuth
        if (-not $token) {
            $errorMsg = "Authentication failed. Exiting."
            Write-Host $errorMsg
            logError $errorMsg
            return
        }

        # Check if the account exists
        Write-Host "Checking if account exists for hostname: $hostname..."
        $existingAccountId = getExistingAccount -token $token

        if ($existingAccountId) {
            Write-Host "Account already exists with ID: $existingAccountId"
            # Proceed to strong account creation
            Write-Host "Proceeding to create strong account..."
            $secretId = strongAccount -token $token
            if (-not $secretId) {
                $errorMsg = "Failed to create strong account. Exiting."
                Write-Host $errorMsg
                logError $errorMsg
                return
            }

            # Call for target set creation after strong account creation
            Invoke-CyberArkTargetSet -token $token -secretId $secretId -hostname $hostname

        } else {
            Write-Host "Account not found. Proceeding with onboarding..."

            # Reset Administrator password and store securely
            Write-Host "Resetting Administrator password..."
            $passwordObject = passwordReset
            if (-not $passwordObject) {
                $errorMsg = "Failed to reset Administrator password. Exiting."
                Write-Host $errorMsg
                logError $errorMsg
                return
            }

            # Extract necessary details for onboarding
            $newPassword = $passwordObject.NewPassword
            $adminName = $passwordObject.AdminName

            # Onboard the new account
            $newAccountId = userOnboard -token $token -newPassword $newPassword -adminName $adminName

            if (-not $newAccountId) {
                $errorMsg = "Failed to onboard new user. Exiting."
                Write-Host $errorMsg
                logError $errorMsg
                return
            }

            # Call for target set creation after new account onboarding
            $secretId = strongAccount -token $token
            if (-not $secretId) {
                $errorMsg = "Failed to create strong account. Exiting."
                Write-Host $errorMsg
                logError $errorMsg
                return
            }

            Invoke-CyberArkTargetSet -token $token -secretId $secretId -hostname $hostname
        }

    } catch {
        logError "Script execution failed. Error: $($_.Exception.Message)"
        Write-Host "An error occurred during script execution. Check the log file for details."
    }
}

# Run the Script
scriptExecute
