# Capture the output of Listdlls.exe
$output = & Listdlls.exe | Out-String

# Initialize variables
$currentPID = $null
$results = @()

# Process each line of the output
foreach ($line in $output -split "`r`n") {
    if ($line -match 'pid:\s*(\d+)') {
        # Extract the PID
        $currentPID = $matches[1]
        $results += [pscustomobject]@{ 
            PID = $currentPID
            DLLs = @() 
        }
    } elseif ($line -match '\.dll') {
        # Extract DLL filename
        $dll = ($line -split '\\')[-1]
        if ($null -ne $currentPID) {
            $result = $results | Where-Object { $_.PID -eq $currentPID }
            if ($result) {
                $result.DLLs += $dll
            }
        }
    }
}

# Output results in a formatted table
$outputFilePath = "data/dll_data.txt"
$results | Format-Table -AutoSize -Wrap -Property PID, @{Name='DLLs';Expression={$_.DLLs -join ', '}} | Out-File -FilePath $outputFilePath
