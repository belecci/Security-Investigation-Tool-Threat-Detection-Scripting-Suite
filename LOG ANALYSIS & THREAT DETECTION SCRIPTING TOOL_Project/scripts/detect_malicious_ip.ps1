# Detects malicious IPs using VirusTotal

# Define parameters
param([string]$AccessLog, [string]$ApiKey)

# Storage
$script:malicious_alerts = 0
$script:malicious_details = @()

# Define function

function Detect-Malicious{
    param([string]$AccessLog, [string]$ApiKey)

    Write-Host "[X] Checking IPs [VirusTotal]"

    Write-Host "[X] Checking top 15 IPs from access.log" -ForegroundColor Cyan

    # Extract TOP IPs from access.log
    $topIPs = Get-Content $AccessLog | ForEach-Object { ($_ -split '\s+') } | Where-Object { $_ -match '(\d{1,3}\.){3}\d{1,3}' } | Group-Object | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object { $_.Name }

    # APIKEY
    $headers = @{ "x-apikey" = $ApiKey}

    # Check each IP
    foreach ($ip in $topIPs) {
        Write-Host " $ip is being Checked..." -ForegroundColor Yellow

        # Sends a GET request to VirusTotal
        try {
            $response = Invoke-RestMethod -Method GET -Uri "https://www.virustotal.com/api/v3/ip_addresses/$ip" -Headers $headers

            # Extracts the response from JSON 
            $malicious = $response.data.attributes.last_analysis_stats.malicious

            Write-Host "[V] Malicious score: $malicious" -ForegroundColor Yellow

            # Check if IP is malicious
            if ($malicious -gt 0) {
                Write-Host "[ALERT] Malicious IP: $ip" -ForegroundColor Red
                Write-Host "Score: $malicious [ALERT]" -ForegroundColor Red

                # Increase alerts
                $script:malicious_alerts++
                $script:malicious_details += " IP: $ip | Score: $malicious"
            } else {
                Write-Host "[SAFE] $ip == NOT MALICIOUS" -ForegroundColor Green 
            }

            # Only 4 IPs/minute
            Start-Sleep 15   
        }
	
	catch {

            Write-Host "[ERROR] Failed to query VirusTotal for $ip" -ForegroundColor Red
        }
    }

    if ($script:malicious_alerts -eq 0) {
        Write-Host " [OK] Malicious IPs not detected." -ForegroundColor Green
    }
}

Detect-Malicious -AccessLog $AccessLog -ApiKey $ApiKey

