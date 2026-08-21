<#
    Get-WASRequestResponseTiming.ps1

    Parses historical WebSphere SystemOut logs (including files shipped by
    Copy-WASHistoricalLogs.ps1) and correlates each outbound request with its
    matching response by the <ControlField> value embedded in the logged XML,
    producing a CSV timing report: ControlField, request time, response time,
    duration.

    LOG ENTRY FORMAT ASSUMED:
        [8/14/26 4:44:39:186 CDT] .......rest of line, possibly followed by
        several more lines (e.g. a pretty-printed XML payload) that belong to
        the same entry, until the next line starting with "[M/d/yy H:mm:ss:fff TZ]"
        is seen.

    HOW REQUEST/RESPONSE PAIRS ARE MATCHED:
        - An entry is a REQUEST if it contains -RequestMarker (default
          "Here is the xml", case-insensitive) AND a <ControlField> element.
        - An entry is a candidate RESPONSE if it contains a <ControlField>
          element and is NOT itself flagged as a request.
        - Requests and responses are matched FIFO per ControlField value, so
          this still works if a value is legitimately reused. A response
          found with no pending request for its ControlField (e.g. the
          request lived in a log file that already rolled off / was deleted)
          is still reported, with a blank request time and
          Status=ResponseWithoutRequest. Any request left pending after all
          files are processed is reported with a blank response time and
          Status=RequestWithoutResponse, instead of being silently dropped.
        - For every response entry, the payload size (in bytes, UTF-8) of
          its enclosing <MyMessage ...>...</MyMessage> element is captured
          in the ResponseSizeBytes column, so unusually large/small
          responses can be spotted alongside their timing.

    DESIGN NOTES (why it looks like this):
      - Files are read in true chronological order across the whole rolling
        set (sorted by the first timestamp found inside each file, not by
        filename), because a request and its response can land in different
        rotated files and rotated file names alone are not a reliable sort
        key across all WAS rotation schemes.
      - Each file is streamed line-by-line (System.IO.StreamReader) rather
        than loaded with Get-Content, so multi-gigabyte historical logs don't
        have to fit in memory at once. Only the small set of still-open
        (unmatched) requests and the final result rows are kept in memory,
        not the raw log text.
      - A quick Contains("<ControlField>") check guards the (slower) regex
        match so entries with no ControlField at all - the overwhelming
        majority of typical WAS log lines - are skipped cheaply.

    USAGE:
        .\Get-WASRequestResponseTiming.ps1 -Path 'C:\WebSphere\LogArchive' -OutputCsv '.\timing.csv'

        .\Get-WASRequestResponseTiming.ps1 -Path '\\fileshare\WASLogArchive' `
            -Filter 'SystemOut*.log*' -OutputCsv 'C:\Reports\WASTiming.csv' -Verbose

        .\Get-WASRequestResponseTiming.ps1 -Path '\\fileshare\WASLogArchive' `
            -StartDateTime '2026-08-21 06:00:00' -EndDateTime '2026-08-21 08:00:00' `
            -OutputCsv 'C:\Reports\WASTiming.csv'

        .\Get-WASRequestResponseTiming.ps1 `
            -LogFiles 'C:\WebSphere\LogArchive\SystemOut_26.08.21_06.08.05.log', `
                      'C:\WebSphere\LogArchive\SystemOut_26.08.21_07.08.05.log' `
            -RequestMarker 'Here is the xml' -OutputCsv '.\timing.csv'

    FILE-NAME DATE FILTERING (-StartDateTime / -EndDateTime):
        WAS names a rotated historical file after the moment it was closed,
        e.g. SystemOut_26.08.21_07.08.05.log -> 2026-08-21 07:08:05. When
        -StartDateTime and/or -EndDateTime are supplied, only files whose
        file-name timestamp falls within that (inclusive) range are read -
        this is a cheap pre-filter to avoid opening files that are entirely
        outside the window of interest, applied before the (still exact,
        per-line) timestamp parsing done while reading each file. A file
        whose name has no parseable timestamp (e.g. the live SystemOut.log)
        is always included, since it cannot be filtered by name. This filter
        only applies when scanning -Path/-Filter; an explicit -LogFiles list
        is used as-is. Because the file-name timestamp marks the end, not
        the start, of a rotated file's content, pass a -StartDateTime a bit
        earlier than your true window if entries near the start of the
        range must not be missed.
#>

[CmdletBinding()]
param(
    # Directory containing the WAS log files to parse (live SystemOut.log
    # plus any rotated historical siblings, e.g. SystemOut_16.08.13_00.00.00.log).
    [Parameter(Mandatory = $true)]
    [string]$Path,

    # Name filter applied within -Path. Matches both the live log and WAS's
    # rotated historical naming convention (SystemOut_<date>_<time>.log).
    [string]$Filter = 'SystemOut*.log*',

    # Explicit list of log files to parse instead of scanning -Path/-Filter.
    # If supplied, -Path/-Filter are ignored.
    [string[]]$LogFiles,

    [string]$OutputCsv = '.\WASRequestResponseTiming.csv',

    # Only include files (when scanning -Path/-Filter) whose file-name
    # timestamp is on or after this date/time, e.g. the "26.08.21_07.08.05"
    # in SystemOut_26.08.21_07.08.05.log. Files with no parseable file-name
    # timestamp are always included. See FILE-NAME DATE FILTERING above.
    [Nullable[datetime]]$StartDateTime,

    # Only include files (when scanning -Path/-Filter) whose file-name
    # timestamp is on or before this date/time. See FILE-NAME DATE
    # FILTERING above.
    [Nullable[datetime]]$EndDateTime,

    # Case-insensitive text that marks an entry as a request.
    [string]$RequestMarker = 'Here is the xml',

    # How many lines to scan at the start of a file when determining its
    # chronological position among the other log files.
    [int]$FileSortProbeLines = 500
)

$ErrorActionPreference = 'Stop'

if ($StartDateTime -and $EndDateTime -and $StartDateTime -gt $EndDateTime) {
    throw "-StartDateTime ($StartDateTime) is after -EndDateTime ($EndDateTime)."
}

# ---------------------------------------------------------------------------
# Compiled regexes (built once, reused for every line/entry).
# ---------------------------------------------------------------------------
$timestampRegex = [System.Text.RegularExpressions.Regex]::new(
    '^\[(?<date>\d{1,2}/\d{1,2}/\d{2,4}) (?<time>\d{1,2}:\d{2}:\d{2}:\d{3}) (?<tz>[A-Za-z]{2,5})\]',
    [System.Text.RegularExpressions.RegexOptions]::Compiled)

$controlFieldOptions = [System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::Singleline
$controlFieldRegex = [System.Text.RegularExpressions.Regex]::new(
    '<ControlField>(?<cf>[^<]*)</ControlField>', $controlFieldOptions)

# Marks the enclosing element around a response's <ControlField>, used to
# measure the response payload size.
$messageStartMarker = '<MyMessage '
$messageEndMarker = '</MyMessage>'

# Matches the date/time WAS embeds in a rotated file's name, e.g.
# SystemOut_26.08.21_07.08.05.log -> 26.08.21_07.08.05 (yy.MM.dd_HH.mm.ss).
$fileNameTimestampRegex = [System.Text.RegularExpressions.Regex]::new(
    '_(?<date>\d{2}\.\d{2}\.\d{2})_(?<time>\d{2}\.\d{2}\.\d{2})\.log$',
    [System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

$timestampFormats = @('M/d/yy H:mm:ss:fff', 'M/d/yyyy H:mm:ss:fff')

function ConvertTo-WASTimestamp {
    param([string]$DateText, [string]$TimeText)

    $combined = "$DateText $TimeText"
    foreach ($fmt in $timestampFormats) {
        $dt = New-Object DateTime
        $ok = [DateTime]::TryParseExact(
            $combined, $fmt, [System.Globalization.CultureInfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::None, [ref]$dt)
        if ($ok) { return $dt }
    }
    return $null
}

# ---------------------------------------------------------------------------
# Determine chronological order of the log files by peeking at the first
# timestamp each one contains (falls back to LastWriteTime if none found,
# e.g. an empty or non-standard file).
# ---------------------------------------------------------------------------
function Get-FirstTimestampInFile {
    param([string]$FilePath, [int]$MaxLines)

    $reader = New-Object System.IO.StreamReader($FilePath, [System.Text.Encoding]::UTF8, $true)
    try {
        $lineCount = 0
        while (-not $reader.EndOfStream -and $lineCount -lt $MaxLines) {
            $line = $reader.ReadLine()
            $lineCount++
            $m = $timestampRegex.Match($line)
            if ($m.Success) {
                $ts = ConvertTo-WASTimestamp -DateText $m.Groups['date'].Value -TimeText $m.Groups['time'].Value
                if ($ts) { return $ts }
            }
        }
    } finally {
        $reader.Dispose()
    }
    return $null
}

function Get-FileNameTimestamp {
    param([string]$FileName)

    $m = $fileNameTimestampRegex.Match($FileName)
    if (-not $m.Success) { return $null }

    $dt = New-Object DateTime
    $ok = [DateTime]::TryParseExact(
        ($m.Groups['date'].Value + '_' + $m.Groups['time'].Value), 'yy.MM.dd_HH.mm.ss',
        [System.Globalization.CultureInfo]::InvariantCulture,
        [System.Globalization.DateTimeStyles]::None, [ref]$dt)
    if ($ok) { return $dt }
    return $null
}

function Test-FileInDateRange {
    param([string]$FileName)

    if (-not $StartDateTime -and -not $EndDateTime) { return $true }

    $ts = Get-FileNameTimestamp -FileName $FileName
    if (-not $ts) { return $true }

    if ($StartDateTime -and $ts -lt $StartDateTime) { return $false }
    if ($EndDateTime -and $ts -gt $EndDateTime) { return $false }
    return $true
}

function Get-OrderedLogFiles {
    param([System.IO.FileInfo[]]$Files)

    $probed = foreach ($f in $Files) {
        $firstTs = Get-FirstTimestampInFile -FilePath $f.FullName -MaxLines $FileSortProbeLines
        $sortKey = if ($firstTs) { $firstTs } else { $f.LastWriteTime }
        Write-Verbose ("Ordering: {0} -> {1}{2}" -f $f.Name, $sortKey, $(if (-not $firstTs) { ' (fallback: LastWriteTime, no timestamp found)' } else { '' }))
        [PSCustomObject]@{ File = $f; SortKey = $sortKey }
    }
    $probed | Sort-Object SortKey, { $_.File.Name } | ForEach-Object { $_.File }
}

# ---------------------------------------------------------------------------
# Correlation state.
# ---------------------------------------------------------------------------
# ControlField value -> Queue of pending request records (FIFO match).
$pending = @{}
$results = New-Object System.Collections.Generic.List[object]

function Get-ResponseSizeBytes {
    param([string]$EntryText)

    $startIdx = $EntryText.IndexOf($messageStartMarker, [StringComparison]::Ordinal)
    if ($startIdx -lt 0) { return $null }

    $endIdx = $EntryText.IndexOf($messageEndMarker, $startIdx, [StringComparison]::Ordinal)
    if ($endIdx -lt 0) { return $null }
    $endIdx += $messageEndMarker.Length

    $element = $EntryText.Substring($startIdx, $endIdx - $startIdx)
    return [System.Text.Encoding]::UTF8.GetByteCount($element)
}

function Add-ResultRow {
    param($ControlField, $RequestTimestamp, $RequestFile, $ResponseTimestamp, $ResponseFile, $ResponseSizeBytes, $Status)

    $duration = $null
    if ($RequestTimestamp -and $ResponseTimestamp) {
        $duration = $ResponseTimestamp - $RequestTimestamp
    }

    $results.Add([PSCustomObject]@{
        ControlField      = $ControlField
        RequestDateTime   = $RequestTimestamp
        ResponseDateTime  = $ResponseTimestamp
        DurationSeconds   = if ($duration) { [math]::Round($duration.TotalSeconds, 3) } else { $null }
        Duration          = if ($duration) { $duration.ToString() } else { $null }
        ResponseSizeBytes = $ResponseSizeBytes
        RequestFile       = $RequestFile
        ResponseFile      = $ResponseFile
        Status            = $Status
    }) | Out-Null
}

function Invoke-LogEntry {
    param([string]$EntryText, [Nullable[DateTime]]$Timestamp, [string]$FileName)

    if (-not $Timestamp) { return }
    if ($EntryText.IndexOf('<ControlField>', [StringComparison]::OrdinalIgnoreCase) -lt 0) { return }

    $cfMatch = $controlFieldRegex.Match($EntryText)
    if (-not $cfMatch.Success) { return }
    $cf = $cfMatch.Groups['cf'].Value

    $isRequest = $EntryText.IndexOf($RequestMarker, [StringComparison]::OrdinalIgnoreCase) -ge 0

    if ($isRequest) {
        if (-not $pending.ContainsKey($cf)) {
            $pending[$cf] = New-Object System.Collections.Generic.Queue[object]
        }
        $pending[$cf].Enqueue([PSCustomObject]@{ Timestamp = $Timestamp; File = $FileName })
        return
    }

    $responseSizeBytes = Get-ResponseSizeBytes -EntryText $EntryText

    if ($pending.ContainsKey($cf) -and $pending[$cf].Count -gt 0) {
        $req = $pending[$cf].Dequeue()
        if ($pending[$cf].Count -eq 0) { $pending.Remove($cf) }
        Add-ResultRow -ControlField $cf -RequestTimestamp $req.Timestamp -RequestFile $req.File `
            -ResponseTimestamp $Timestamp -ResponseFile $FileName -ResponseSizeBytes $responseSizeBytes -Status 'Matched'
    } else {
        Add-ResultRow -ControlField $cf -RequestTimestamp $null -RequestFile $null `
            -ResponseTimestamp $Timestamp -ResponseFile $FileName -ResponseSizeBytes $responseSizeBytes -Status 'ResponseWithoutRequest'
    }
}

function Read-LogFile {
    param([string]$FilePath)

    $fileName = Split-Path -Leaf $FilePath
    $reader = New-Object System.IO.StreamReader($FilePath, [System.Text.Encoding]::UTF8, $true)
    try {
        $buffer = New-Object System.Text.StringBuilder
        $currentTimestamp = $null
        $lineNum = 0

        while (-not $reader.EndOfStream) {
            $line = $reader.ReadLine()
            $lineNum++
            $m = $timestampRegex.Match($line)

            if ($m.Success) {
                if ($currentTimestamp) {
                    Invoke-LogEntry -EntryText $buffer.ToString() -Timestamp $currentTimestamp -FileName $fileName
                }
                $buffer = New-Object System.Text.StringBuilder
                [void]$buffer.AppendLine($line)
                $currentTimestamp = ConvertTo-WASTimestamp -DateText $m.Groups['date'].Value -TimeText $m.Groups['time'].Value
            } else {
                [void]$buffer.AppendLine($line)
            }
        }

        if ($currentTimestamp) {
            Invoke-LogEntry -EntryText $buffer.ToString() -Timestamp $currentTimestamp -FileName $fileName
        }

        Write-Verbose ("Processed {0} ({1} lines)." -f $fileName, $lineNum)
    } finally {
        $reader.Dispose()
    }
}

# ---------------------------------------------------------------------------
# Main.
# ---------------------------------------------------------------------------
if ($LogFiles) {
    $files = foreach ($p in $LogFiles) { Get-Item -LiteralPath $p }
} else {
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Path '$Path' does not exist."
    }
    $files = @(Get-ChildItem -LiteralPath $Path -Filter $Filter -File)
    if (-not $files -or $files.Count -eq 0) {
        throw "No files matching filter '$Filter' found under '$Path'."
    }

    if ($StartDateTime -or $EndDateTime) {
        $beforeCount = $files.Count
        $files = @($files | Where-Object { Test-FileInDateRange -FileName $_.Name })
        Write-Verbose ("Date range filter ({0} to {1}): {2} of {3} file(s) kept." -f `
            $(if ($StartDateTime) { $StartDateTime } else { '-inf' }), `
            $(if ($EndDateTime) { $EndDateTime } else { '+inf' }), $files.Count, $beforeCount)
        if ($files.Count -eq 0) {
            throw "No files matching filter '$Filter' under '$Path' fall within the requested date/time range."
        }
    }
}

Write-Verbose ("Found {0} log file(s). Determining chronological order..." -f $files.Count)
$orderedFiles = Get-OrderedLogFiles -Files $files

foreach ($file in $orderedFiles) {
    Write-Verbose ("Reading {0}..." -f $file.FullName)
    Read-LogFile -FilePath $file.FullName
}

# Any request that never saw a matching response.
foreach ($cf in @($pending.Keys)) {
    while ($pending[$cf].Count -gt 0) {
        $req = $pending[$cf].Dequeue()
        Add-ResultRow -ControlField $cf -RequestTimestamp $req.Timestamp -RequestFile $req.File `
            -ResponseTimestamp $null -ResponseFile $null -Status 'RequestWithoutResponse'
    }
}

# ---------------------------------------------------------------------------
# Output.
# ---------------------------------------------------------------------------
$sortedResults = $results | Sort-Object {
    if ($_.RequestDateTime) { $_.RequestDateTime } else { $_.ResponseDateTime }
}

$csvRows = $sortedResults | Select-Object `
    ControlField,
    @{N = 'RequestDateTime'; E = { if ($_.RequestDateTime) { $_.RequestDateTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } else { '' } } },
    @{N = 'ResponseDateTime'; E = { if ($_.ResponseDateTime) { $_.ResponseDateTime.ToString('yyyy-MM-dd HH:mm:ss.fff') } else { '' } } },
    Duration,
    DurationSeconds,
    ResponseSizeBytes,
    Status,
    RequestFile,
    ResponseFile

$csvRows | Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Encoding UTF8

$matched = @($sortedResults | Where-Object { $_.Status -eq 'Matched' })
$noResponse = @($sortedResults | Where-Object { $_.Status -eq 'RequestWithoutResponse' })
$noRequest = @($sortedResults | Where-Object { $_.Status -eq 'ResponseWithoutRequest' })

Write-Host ""
Write-Host "Report written to: $OutputCsv"
Write-Host ("  Matched request/response pairs : {0}" -f $matched.Count)
Write-Host ("  Requests with no response found : {0}" -f $noResponse.Count)
Write-Host ("  Responses with no request found : {0}" -f $noRequest.Count)

if ($matched.Count -gt 0) {
    $durations = $matched | ForEach-Object { $_.DurationSeconds }
    $stats = $durations | Measure-Object -Average -Minimum -Maximum
    Write-Host ("  Duration (sec) - min/avg/max    : {0:N3} / {1:N3} / {2:N3}" -f $stats.Minimum, $stats.Average, $stats.Maximum)

    $sizes = @($matched | Where-Object { $null -ne $_.ResponseSizeBytes } | ForEach-Object { $_.ResponseSizeBytes })
    if ($sizes.Count -gt 0) {
        $sizeStats = $sizes | Measure-Object -Average -Minimum -Maximum
        Write-Host ("  Response size (bytes) - min/avg/max : {0:N0} / {1:N0} / {2:N0}" -f $sizeStats.Minimum, $sizeStats.Average, $sizeStats.Maximum)
    }
}
