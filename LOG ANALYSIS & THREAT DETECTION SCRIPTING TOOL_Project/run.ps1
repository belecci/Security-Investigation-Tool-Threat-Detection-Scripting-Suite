# Security Investigation TOOL
# Calls all detection tools

# Allow scripts to run
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force

# Build file paths
$DATASET_DIR = Join-Path $PSScriptRoot "ProjectDataset"
$AUTH_LOG = Join-Path $DATASET_DIR  "auth.log"
$ACCESS_LOG = Join-Path $DATASET_DIR  "access.log"
$PS_LOG = Join-Path $DATASET_DIR  "powershell_log.txt"
$IOC_FILE = Join-Path $DATASET_DIR  "ioc.txt"
$REPORT_FILE = Join-Path $PSScriptRoot "investigation_report.txt"

# Storage
$script:brute_alerts = 0
$script:ioc_hits = 0
$script:ps_alerts = 0
$script:malicious_alerts = 0
$script:top_attacker = "None"
$script:brute_details = @()
$script:ioc_details = @()
$script:ps_details = @()
$script:malicious_details = @()

# Banner
Write-Host ("-" * 77) -ForegroundColor DarkCyan
Write-Host " * SECURITY INVESTIGATION TOOL * " -ForegroundColor Red
Write-Host ("=" * 77) -ForegroundColor DarkCyan
Write-Host " --Used DataSet--> $DATASET_DIR" -ForegroundColor Red
Write-Host ""
Write-Host " --Out Report--> $REPORT_FILE" -ForegroundColor Red
Write-Host ("=" * 77) -ForegroundColor DarkCyan

# Input API key
$VT_API_KEY = Read-Host "Enter your VirusTotal API key"

Write-Host "------ Calling BruteForce Detection ------" -ForegroundColor Green
. "$PSScriptRoot\scripts\detect_bruteforce.ps1"   -AuthLog $AUTH_LOG
Write-Host "------ END BruteForce Detection ------"
Write-Host ""

Write-Host "------ Calling IOC Detection ------" -ForegroundColor Green
. "$PSScriptRoot\scripts\detect_ioc.ps1" -AuthLog $AUTH_LOG -AccessLog $ACCESS_LOG -IocSamples $IOC_FILE
Write-Host "------ END IOC Detection ------"
Write-Host ""

Write-Host "------ Calling MALICIOUS IP Detection ------" -ForegroundColor Green
. "$PSScriptRoot\scripts\detect_malicious_ip.ps1" -AccessLog $ACCESS_LOG -ApiKey $VT_API_KEY
Write-Host "------ END MALICIOUS IP Detection ------"
Write-Host ""

Write-Host "------ Calling SUSPICIOUS PS Detection ------" -ForegroundColor Green
. "$PSScriptRoot\scripts\detect_powershell.ps1" -PowerLog $PS_LOG
Write-Host "------ END SUSPICIOUS PS Detection ------"
Write-Host ""

# Define Function
function Report-Generation {
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'

    # Add all alerts
    $alertsCount = $script:brute_alerts + $script:ioc_hits + $script:ps_alerts + $script:malicious_alerts

    # Risk level
    if ($alertsCount -eq 0) {
        $risk = "NO RISK"
    } elseif ($alertsCount -le 2) {
        $risk = "Low"
    } elseif ($alertsCount -le 5) {
        $risk = "Medium"
    } elseif ($alertsCount -le 9) {
        $risk = "High"
    } else {
        $risk = "CR!T!CAL"
    }

    # Risk colour
    $riskColor = switch ($risk) {
        "NO RISK"  { "Blue"    }
        "Low"      { "Green"   }
        "Medium"   { "Yellow"  }
        "High"     { "Red"     }
        "CR!T!CAL" { "Magenta" }
    }

    # Summary
    Write-Host ""
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "         INVESTIGATION SUMMARY" -ForegroundColor Cyan
    Write-Host ("=" * 60) -ForegroundColor DarkCyan
    Write-Host "  SSH Brute Force Alerts    : $($script:brute_alerts)"
    Write-Host "  IOC Matches               : $($script:ioc_hits)"
    Write-Host "  Suspicious PowerShell     : $($script:ps_alerts)"
    Write-Host "  VirusTotal Malicious IPs  : $($script:malicious_alerts)"
    Write-Host "  ------------------------------------"
    Write-Host "  Total Alerts              : $alertsCount"
    Write-Host "  Top Attacker IP           : $($script:top_attacker)"
    Write-Host "  Risk Level                : $risk" -ForegroundColor $riskColor
    Write-Host ("=" * 60) -ForegroundColor DarkCyan

    # Build report content
    $r = @()
    $r += "============================================================"
    $r += "         SECURITY INVESTIGATION REPORT"
    $r += "         Generated : $timestamp"
    $r += "         Student   : B00170371"
    $r += "============================================================"
    $r += ""
    $r += "SUMMARY"
    $r += "--------"
    $r += "Total Alerts   : $alertsCount"
    $r += "Risk Level     : $risk"
    $r += "Top Attacker   : $($script:top_attacker)"
    $r += ""
    $r += "------------------------------------------------------------"
    $r += "DETECTION 1 - SSH Brute Force"
    $r += "Alerts : $($script:brute_alerts)"
    if ($script:brute_details.Count -gt 0) { $r += $script:brute_details }
    else { $r += "  No brute force activity detected." }
    $r += ""
    $r += "------------------------------------------------------------"
    $r += "DETECTION 2 - IOC Matches"
    $r += "Alerts : $($script:ioc_hits)"
    if ($script:ioc_details.Count -gt 0) { $r += $script:ioc_details }
    else { $r += "  No IOC matches found." }
    $r += ""
    $r += "------------------------------------------------------------"
    $r += "DETECTION 3 - Suspicious PowerShell"
    $r += "Alerts : $($script:ps_alerts)"
    if ($script:ps_details.Count -gt 0) { $r += $script:ps_details }
    else { $r += "  No suspicious PowerShell patterns found." }
    $r += ""
    $r += "------------------------------------------------------------"
    $r += "DETECTION 4 - VirusTotal IP Reputation"
    $r += "Alerts : $($script:malicious_alerts)"
    if ($script:malicious_details.Count -gt 0) { $r += $script:malicious_details }
    else { $r += "  No malicious IPs found." }
    $r += ""
    $r += "============================================================"
    $r += "END OF REPORT"
    $r += "============================================================"

    # Save report to file
    $r | Out-File -FilePath $REPORT_FILE -Encoding UTF8

    Write-Host ""
    Write-Host "[+] Report saved to: $REPORT_FILE" -ForegroundColor Green
}

# Call the report function
Report-Generation