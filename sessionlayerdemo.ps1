# OSI Layer 5 - Session Layer Demonstration Scripts

Write-Host "=== OSI Layer 5: Session Layer Protocol Demonstrations ===" -ForegroundColor Cyan
Write-Host "These demos show real session layer protocols managing connections between applications" -ForegroundColor Yellow
Write-Host ""

function Show-SMBSessions {
    Write-Host "=== Demo 1: SMB (Server Message Block) Sessions ===" -ForegroundColor Green
    Write-Host "SMB manages file sharing sessions and network communication"
    Write-Host ""
    
    Write-Host "Current SMB Sessions on this system:" -ForegroundColor Yellow
    try {
        # Show active SMB sessions
        Get-SmbSession | Format-Table -AutoSize
        
        Write-Host "`nSMB Shares (what sessions can connect to):" -ForegroundColor Yellow
        Get-SmbShare | Format-Table Name, Path, Description -AutoSize
        
        Write-Host "`nSMB Client connections:" -ForegroundColor Yellow
        Get-SmbConnection | Format-Table ServerName, ShareName, UserName, NumOpens -AutoSize
        
    } catch {
        Write-Host "No active SMB sessions found or insufficient permissions" -ForegroundColor Red
        Write-Host "This is normal on a standalone system with no network shares active"
    }
    
    Write-Host "`nKey Session Layer functions SMB provides:" -ForegroundColor Cyan
    Write-Host "- Session establishment with authentication"
    Write-Host "- Session management and state tracking"
    Write-Host "- Multiple file operations within the same session"
    Write-Host "- Graceful session termination"
    Write-Host ""
}

function Show-RDPSessions {
    Write-Host "=== Demo 2: RDP (Remote Desktop Protocol) Sessions ===" -ForegroundColor Green
    Write-Host "RDP creates and manages remote desktop sessions"
    Write-Host ""
    
    Write-Host "Current RDP/Terminal Server Sessions:" -ForegroundColor Yellow
    try {
        # Show current logon sessions
        query session 2>$null | Out-String
        
        Write-Host "RDP Session Configuration:" -ForegroundColor Yellow
        Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' | 
            Select-Object fDenyTSConnections, TSEnabled | Format-List
            
    } catch {
        Write-Host "Could not retrieve RDP session information" -ForegroundColor Red
    }
    
    Write-Host "Session Layer aspects of RDP:" -ForegroundColor Cyan
    Write-Host "- Establishes authenticated sessions with remote systems"
    Write-Host "- Manages session state (keyboard, mouse, display)"
    Write-Host "- Handles session persistence and reconnection"
    Write-Host "- Controls session termination and cleanup"
    Write-Host ""
}

function Show-DatabaseSessions {
    Write-Host "=== Demo 3: Database Connection Sessions ===" -ForegroundColor Green
    Write-Host "Demonstrating SQL Server session management"
    Write-Host ""
    
    try {
        # Check if SQL Server services are running
        $sqlServices = Get-Service | Where-Object {$_.Name -like "*SQL*"}
        if ($sqlServices) {
            Write-Host "SQL Server Services (manage database sessions):" -ForegroundColor Yellow
            $sqlServices | Format-Table Name, Status, StartType -AutoSize
        } else {
            Write-Host "No SQL Server services found on this system" -ForegroundColor Red
        }
        
        # Show ODBC data sources (session connection points)
        Write-Host "`nODBC Data Sources (session connection endpoints):" -ForegroundColor Yellow
        try {
            Get-OdbcDsn | Select-Object Name, DsnType, DriverName | Format-Table -AutoSize
        } catch {
            Write-Host "Could not enumerate ODBC data sources" -ForegroundColor Red
        }
        
    } catch {
        Write-Host "Database session information unavailable" -ForegroundColor Red
    }
    
    Write-Host "Database Session Layer functions:" -ForegroundColor Cyan
    Write-Host "- Connection pooling and session reuse"
    Write-Host "- Transaction context management"
    Write-Host "- Authentication and authorization per session"
    Write-Host "- Session timeout and cleanup"
    Write-Host ""
}

function Show-ProcessCommunication {
    Write-Host "=== Demo 4: Inter-Process Communication Sessions ===" -ForegroundColor Green
    Write-Host "Named pipes and other IPC mechanisms create sessions between processes"
    Write-Host ""
    
    Write-Host "Active Named Pipes (IPC sessions):" -ForegroundColor Yellow
    try {
        # Show named pipes
        Get-ChildItem \\.\pipe\ | Select-Object -First 10 Name | Format-Table -AutoSize
        Write-Host "... (showing first 10 of many named pipes)"
        
        Write-Host "`nProcesses with network connections (potential sessions):" -ForegroundColor Yellow
        Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | 
            Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess |
            Sort-Object OwningProcess | Select-Object -First 10 | Format-Table -AutoSize
            
    } catch {
        Write-Host "Could not enumerate IPC sessions" -ForegroundColor Red
    }
    
    Write-Host "IPC Session Layer characteristics:" -ForegroundColor Cyan
    Write-Host "- Establishes communication channels between processes"
    Write-Host "- Manages message queuing and synchronization"
    Write-Host "- Handles session cleanup when processes terminate"
    Write-Host ""
}

function Show-WebSessions {
    Write-Host "=== Demo 5: Web Browser Session Management ===" -ForegroundColor Green
    Write-Host "Web browsers maintain sessions with web servers"
    Write-Host ""
    
    Write-Host "Browser processes that manage web sessions:" -ForegroundColor Yellow
    try {
        Get-Process | Where-Object {$_.Name -match "chrome|firefox|edge|iexplore"} |
            Select-Object Name, Id, @{Name="Memory(MB)";Expression={[math]::Round($_.WorkingSet/1MB,2)}} |
            Format-Table -AutoSize
            
        Write-Host "`nActive network connections from browsers:" -ForegroundColor Yellow
        $browserProcs = Get-Process | Where-Object {$_.Name -match "chrome|firefox|edge|iexplore"} | Select-Object -ExpandProperty Id
        if ($browserProcs) {
            Get-NetTCPConnection | Where-Object {$_.OwningProcess -in $browserProcs -and $_.State -eq "Established"} |
                Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort | 
                Select-Object -First 5 | Format-Table -AutoSize
        }
        
    } catch {
        Write-Host "No browser processes found or connection information unavailable" -ForegroundColor Red
    }
    
    Write-Host "Web Session Layer functions:" -ForegroundColor Cyan
    Write-Host "- HTTP session management with cookies"
    Write-Host "- HTTPS encrypted session establishment"
    Write-Host "- Session persistence across multiple requests"
    Write-Host "- WebSocket persistent sessions for real-time communication"
    Write-Host ""
}

function Demonstrate-SessionLifecycle {
    Write-Host "=== Session Lifecycle Demonstration ===" -ForegroundColor Green
    Write-Host "Creating a simple PowerShell remoting session to demonstrate session management"
    Write-Host ""
    
    try {
        Write-Host "Step 1: Session Establishment" -ForegroundColor Yellow
        Write-Host "Creating a new PS session to localhost..."
        
        $session = New-PSSession -ComputerName localhost -Name "DemoSession"
        Write-Host "Session created with ID: $($session.Id)"
        
        Write-Host "`nStep 2: Session Management" -ForegroundColor Yellow
        Write-Host "Session details:"
        $session | Format-List Name, State, ComputerName, InstanceId
        
        Write-Host "Executing commands within the session..."
        Invoke-Command -Session $session -ScriptBlock { 
            "Hello from session! Current time: $(Get-Date)"
            "Process ID in session: $PID"
            "Session maintains state between commands"
        }
        
        Write-Host "`nStep 3: Session Termination" -ForegroundColor Yellow
        Write-Host "Closing the session..."
        Remove-PSSession -Session $session
        Write-Host "Session closed and resources cleaned up"
        
    } catch {
        Write-Host "PowerShell remoting may not be enabled: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "This demonstrates the three phases of session management even when it fails!"
    }
    
    Write-Host "`nSession Layer Key Concepts Demonstrated:" -ForegroundColor Cyan
    Write-Host "- Establishment: Authentication, negotiation, resource allocation"
    Write-Host "- Management: State maintenance, command execution, error handling"  
    Write-Host "- Termination: Graceful cleanup, resource release"
    Write-Host ""
}

function Show-SessionLayerSummary {
    Write-Host "=== Session Layer (OSI Layer 5) Summary ===" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "Key Functions:" -ForegroundColor Cyan
    Write-Host "• Session Establishment - Setting up communication between applications"
    Write-Host "• Session Management - Maintaining state and controlling data flow"
    Write-Host "• Session Termination - Gracefully closing connections"
    Write-Host "• Dialog Control - Managing full-duplex, half-duplex, or simplex communication"
    Write-Host "• Session Checkpointing - Allowing recovery from interruptions"
    Write-Host ""
    
    Write-Host "Real-World Examples:" -ForegroundColor Cyan
    Write-Host "• SQL Database Sessions (connection pooling, transaction management)"
    Write-Host "• SMB File Sharing (network file access sessions)"
    Write-Host "• RPC Sessions (remote procedure call management)"
    Write-Host "• Web Sessions (HTTP cookies, WebSocket connections)"
    Write-Host "• SSH Sessions (secure shell remote access)"
    Write-Host ""
    
    Write-Host "Why It Matters:" -ForegroundColor Cyan
    Write-Host "• Provides reliable communication channels for applications"
    Write-Host "• Manages complex multi-step processes"
    Write-Host "• Enables session persistence and recovery"
    Write-Host "• Handles authentication and authorization"
    Write-Host "• Allows multiplexing of multiple sessions over single connections"
}

# Main execution
Write-Host "Choose a demonstration:" -ForegroundColor White
Write-Host "1. SMB Sessions"
Write-Host "2. RDP Sessions"
Write-Host "3. Database Sessions"
Write-Host "4. Process Communication"
Write-Host "5. Web Sessions"
Write-Host "6. Session Lifecycle Demo"
Write-Host "7. Show All Demos"
Write-Host "8. Session Layer Summary"
Write-Host ""

$choice = Read-Host "Enter choice (1-8)"

switch ($choice) {
    "1" { Show-SMBSessions }
    "2" { Show-RDPSessions }
    "3" { Show-DatabaseSessions }
    "4" { Show-ProcessCommunication }
    "5" { Show-WebSessions }
    "6" { Demonstrate-SessionLifecycle }
    "7" { 
        Show-SMBSessions
        Show-RDPSessions
        Show-DatabaseSessions
        Show-ProcessCommunication
        Show-WebSessions
        Demonstrate-SessionLifecycle
        Show-SessionLayerSummary
    }
    "8" { Show-SessionLayerSummary }
    default { 
        Write-Host "Running all demos..." -ForegroundColor Yellow
        Show-SMBSessions
        Show-RDPSessions
        Show-DatabaseSessions
        Show-ProcessCommunication
        Show-WebSessions
        Demonstrate-SessionLifecycle
        Show-SessionLayerSummary
    }
}

Write-Host "`n=== Demo Complete ===" -ForegroundColor Green
Write-Host "These examples show how Layer 5 manages sessions between applications across networks." -ForegroundColor Yellow
