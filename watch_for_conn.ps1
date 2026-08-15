# Run PowerShell as Administrator
# Watches for Windows Filtering Platform Event ID 5156
# and reports connections to 85.203.46.184 or remote port 8080.

# Ensure is enabled: auditpol /set /subcategory:"Filtering Platform Connection" /success:enable
# Check: auditpol /get /subcategory:"Filtering Platform Connection"

$TargetIP   = "85.203.46.184" #change to IP to watch
$TargetPort = 8080 #change to port to watch

Write-Host "Enabling Windows Filtering Platform connection auditing..." -ForegroundColor Cyan
auditpol /set /subcategory:"Filtering Platform Connection" /success:enable | Out-Host

Write-Host ""
Write-Host "Current audit setting:" -ForegroundColor Cyan
auditpol /get /subcategory:"Filtering Platform Connection" | Out-Host

Write-Host ""
Write-Host "Watching for connections to $TargetIP or remote port $TargetPort..." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to stop." -ForegroundColor Yellow
Write-Host ""

$StartTime = Get-Date

while ($true) {

    $Now = Get-Date

    $Events = Get-WinEvent -FilterHashtable @{
        LogName   = "Security"
        Id        = 5156
        StartTime = $StartTime
        EndTime   = $Now
    } -ErrorAction SilentlyContinue

    foreach ($Event in $Events) {

        if (
            $Event.Message -match [regex]::Escape($TargetIP) -or
            $Event.Message -match "Destination Port:\s+$TargetPort"
        ) {

            Write-Host "==========================================" -ForegroundColor Red
            Write-Host "MATCH FOUND: $($Event.TimeCreated)" -ForegroundColor Red
            Write-Host "==========================================" -ForegroundColor Red

            Write-Host $Event.Message

            # Try to extract useful fields
            $ProcessID = $null
            $AppName   = $null
            $SrcIP     = $null
            $SrcPort   = $null
            $DstIP     = $null
            $DstPort   = $null

            if ($Event.Message -match "Process ID:\s+(\d+)") {
                $ProcessID = [int]$Matches[1]
            }

            if ($Event.Message -match "Application Name:\s+(.+)") {
                $AppName = $Matches[1].Trim()
            }

            if ($Event.Message -match "Source Address:\s+([^\r\n]+)") {
                $SrcIP = $Matches[1].Trim()
            }

            if ($Event.Message -match "Source Port:\s+(\d+)") {
                $SrcPort = $Matches[1]
            }

            if ($Event.Message -match "Destination Address:\s+([^\r\n]+)") {
                $DstIP = $Matches[1].Trim()
            }

            if ($Event.Message -match "Destination Port:\s+(\d+)") {
                $DstPort = $Matches[1]
            }

            Write-Host ""
            Write-Host "Summary" -ForegroundColor Green
            Write-Host "-------"
            Write-Host "Application : $AppName"
            Write-Host "PID         : $ProcessID"
            Write-Host "Source      : ${SrcIP}:${SrcPort}"
            Write-Host "Destination : ${DstIP}:${DstPort}"

            if ($ProcessID) {
                Write-Host ""
                Write-Host "Current process information:" -ForegroundColor Green

                Get-Process -Id $ProcessID -ErrorAction SilentlyContinue |
                    Select-Object Id, ProcessName, Path |
                    Format-List

                Write-Host "Services running under this PID:" -ForegroundColor Green
                tasklist /svc /fi "PID eq $ProcessID"
            }

            if ($AppName -and (Test-Path $AppName)) {
                Write-Host ""
                Write-Host "Executable signature:" -ForegroundColor Green
                Get-AuthenticodeSignature $AppName |
                    Select-Object Status, StatusMessage, SignerCertificate |
                    Format-List

                Write-Host "SHA256:" -ForegroundColor Green
                Get-FileHash $AppName -Algorithm SHA256 |
                    Format-List
            }

            Write-Host ""
        }
    }

    $StartTime = $Now
    Start-Sleep -Seconds 2
}
