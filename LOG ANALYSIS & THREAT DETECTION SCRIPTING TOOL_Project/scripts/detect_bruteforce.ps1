# detect_bruteforce - Detects BruteForce SSH login attempts from auth.log

param(
    # Declare $AuthLog as parameter, that accepts file path
    [string]$AuthLog
)

# Hardcode the threshold
$brute_threshold = 4

# Storage
$script:brute_alerts = 0
$script:top_attacker = "None"
$script:brute_details = @()
$maxCount = 0

# Define function
function Detect-BruteForce {

    param([string]$AuthLog)

    Write-Host "[X] Checking SSH brute force attempts..."

    # Scan lines
    $FailedLogs = Select-String -Path $AuthLog -Pattern "Failed password|authentication failure"

    # If failed logins not found then exit
    if (-not $FailedLogs) {
        Write-Host "[v] Failed Logins not found."
        return
    }

    # Extract IPs
    $ipList = foreach ($line in $FailedLogs) {
        if ($line.Line -match '(\d{1,3}\.){3}\d{1,3}') {
            $matches[0]
        }
    }

    # Group identical IPs
    $ipCounts = $ipList | Group-Object | Sort-Object Count -Descending

    foreach ($ipCount in $ipCounts) {

        $ip = $ipCount.Name
        $count = $ipCount.Count

        # Check for brute force
        if ($count -ge $brute_threshold) {

            Write-Host "[ALERT] Brute Force Detected from $ip with $count attempts" -ForegroundColor Red

            $script:brute_alerts++
            $script:brute_details += "  - IP: $ip | Attempts: $count"

            if ($count -gt $maxCount) {
                $maxCount = $count
                $script:top_attacker = $ip
            }
        }
    }

    if ($script:brute_alerts -eq 0) {
        Write-Host "[v] No Brute Force activity Detected." -ForegroundColor Green
    }
    else {
        Write-Host "[!!!] Attacker with most Brute Force attempts: $($script:top_attacker)" -ForegroundColor Yellow
    }
}

# Run detection
Detect-BruteForce -AuthLog $AuthLog
