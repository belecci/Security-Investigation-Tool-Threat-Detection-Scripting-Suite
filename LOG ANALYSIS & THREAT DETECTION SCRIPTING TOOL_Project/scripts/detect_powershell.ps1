# Detect Suspicious PowerShell executions from powershell_log.txt

# Set parameters
param([string]$PowerLog)

# Storage
$script:ps_alerts = 0
$script:ps_details = @()

# Suspicious patterns
$susPatterns = @('ExecutionPolicy Bypass','Invoke-Expression','hidden','EncodedCommand','DownloadString','DownloadFile','CurrentVersion\\Run','StartProcess*cmd')

# Define function
function Detect-SusPS {

    param([string]$PowerLog)

    Write-Host "[X] Checking PowerShell log..."

    # Search log
    foreach ($pattern in $susPatterns) {

        $susFound = Select-String -Path $PowerLog -Pattern $pattern -CaseSensitive:$false

        if ($susFound) {

            Write-Host "[ALERT] Suspicious PS Pattern found: '$pattern'" -ForegroundColor Red
            Write-Host "[INFO] Appeared ($($susFound.Count) times)" -ForegroundColor Yellow

            $script:ps_alerts++

            # Store line details
            foreach ($entry in $susFound) {
                $script:ps_details += " - Line $($entry.LineNumber): $($entry.Line.Trim())"
            }
        }
    }

    if ($script:ps_alerts -eq 0) {
        Write-Host "[v] Suspicious PS Patterns not detected." -ForegroundColor Green
    }
}

# Run function
Detect-SusPS -PowerLog $PowerLog
