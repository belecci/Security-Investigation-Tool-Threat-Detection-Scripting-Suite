# Checks Malicious IPs and WebPaths from ioc.txt across auth.log and access.log

# Set parameters
param([string]$AuthLog,[string]$AccessLog,[string]$IocSamples)

# Storage
$script:ioc_hits = 0
$script:ioc_details = @()

# Define Function
function IOC-Detection {

    param([string]$AuthLog,[string]$AccessLog,[string]$IocSamples)

    Write-Host "[X] Checking IOC across logs..."

    # Read IOC file and remove comments/blank lines
    $ioc_indicators = Get-Content $IocSamples | Where-Object {
        $_.Trim() -ne "" -and $_ -notmatch "^#"
    }

    foreach ($ioc in $ioc_indicators) {

        $ioc = $ioc.Trim()
        $found = $false

        # Search auth.log
        if (Select-String -Path $AuthLog -Pattern $ioc -Quiet) {
            Write-Host "[ALERT] IOC MATCHED in auth.log: $ioc" -ForegroundColor Red
            $found = $true
        }

        # Search access.log
        if (Select-String -Path $AccessLog -Pattern $ioc -Quiet) {
            Write-Host "[ALERT] IOC MATCHED in access.log: $ioc" -ForegroundColor Red
            $found = $true
        }

        # Record detection
        if ($found) {

            $script:ioc_hits++
            $script:ioc_details += " IOC Matched: $ioc"
        }
    }

    # Summary
    if ($script:ioc_hits -eq 0) {
        Write-Host "[OK] No IOC detected in logs." -ForegroundColor Green
    }
    else {
        Write-Host "[X] Total IOC Matches: $script:ioc_hits" -ForegroundColor Yellow
    }
}

# Run detection
IOC-Detection -AuthLog $AuthLog -AccessLog $AccessLog -IocSamples $IocSamples
