$root  = "<insert_the_domain_here>"
$paths = "/index.php","/wp-login.php","/xmlrpc.php","/administrator/"

Write-Host "Pulling subdomains from crt.sh (expired certificates excluded at source)..." -ForegroundColor Cyan

# &exclude=expired tells crt.sh to return only active certificates, so every host below comes from a currently valid cert.
$crtUrl = "https://crt.sh/?q=%25.$root&output=json&exclude=expired"

# crt.sh often returns 502/503 errors or times out, and these failures are usually temporary. The script retries up to 5 time, with a maximum timeout of 60 seconds per request.
$maxAttempts = 5
$ct = $null
for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
    try {
        $ct = Invoke-RestMethod $crtUrl -TimeoutSec 60 `
                -Headers @{ "User-Agent" = "phpfinder" } -ErrorAction Stop
        if ($ct) { break }
        # 200 but empty body can happen under load; treat it as a retryable miss.
        throw "empty response"
    } catch {
        $msg = ($_.Exception.Message -split "`n")[0].Trim()
        if ($attempt -lt $maxAttempts) {
            $wait = [math]::Min(30, 5 * $attempt)
            Write-Host "  crt.sh attempt $attempt/$maxAttempts failed: $msg. Retrying in ${wait}s..." -ForegroundColor Yellow
            Start-Sleep -Seconds $wait
        } else {
            Write-Host "  crt.sh attempt $attempt/$maxAttempts failed: $msg." -ForegroundColor Yellow
        }
    }
}

if (-not $ct) {
    Write-Host "`nBailing out: crt.sh never returned data after $maxAttempts attempts." -ForegroundColor Red
    Write-Host "This is a crt.sh-side outage (502/503/timeout), not your query. Wait a few minutes and re-run," -ForegroundColor Red
    Write-Host "or sanity-check the domain in a browser: $($crtUrl -replace '&output=json','')" -ForegroundColor Red
    return
}

# Build a host→cert map and keep only the cert with the latest expiry for each host, ensuring issued and expiry dates stay consistent.
$certInfo = @{}   # hostname -> @{ Issued; Expires; ExpiresRaw }

foreach ($cert in $ct) {
    [datetime]$nb = [datetime]::MinValue
    [datetime]$na = [datetime]::MinValue
    $okNb = [datetime]::TryParse($cert.not_before, [ref]$nb)
    $okNa = [datetime]::TryParse($cert.not_after,  [ref]$na)
    $issuedStr  = if ($okNb) { $nb.ToString("yyyy-MM-dd") } else { "" }
    $expiresStr = if ($okNa) { $na.ToString("yyyy-MM-dd") } else { "" }

    foreach ($name in ($cert.name_value -split "`n")) {
        $hn = $name.Trim().ToLower()
        $hn = $hn -replace '^www\.', ''              # normalize: resolve the base host, not the www. SAN
        if ($hn -notlike "*.$root")  { continue }   # must be under the root domain
        if ($hn -match '\*')         { continue }   # skip wildcard entries
        if ((($hn -replace "\.$root$","") -split '\.').Count -gt 2) { continue }  # depth limit

        if (-not $certInfo.ContainsKey($hn) -or $na -gt $certInfo[$hn].ExpiresRaw) {
            $certInfo[$hn] = [pscustomobject]@{
                Issued     = $issuedStr
                Expires    = $expiresStr
                ExpiresRaw = $na
            }
        }
    }
}

$subs = $certInfo.Keys | Sort-Object -Unique

Write-Host "Found $($subs.Count) candidate hosts. Resolving..." -ForegroundColor Cyan

# Resolve each host once and store the host/IP pair to avoid duplicate lookups; print failed DNS lookups so it's clear which hosts didn’t resolve.
$live      = [System.Collections.Generic.List[object]]::new()
$dnsFailed = 0

foreach ($s in $subs) {
    try {
        $dns = Resolve-DnsName $s -Type A -ErrorAction Stop |
               Where-Object { $_.IPAddress } | Select-Object -First 1
        if ($dns) {
            $live.Add([pscustomobject]@{ Host = $s; IP = $dns.IPAddress })
        } else {
            # Name resolved but returned no A record (e.g. CNAME-only / AAAA-only).
            $dnsFailed++
            Write-Host ("  [DNS FAIL] {0,-45} no A record returned" -f $s) -ForegroundColor DarkYellow
        }
    } catch {
        # True resolution failure: NXDOMAIN, SERVFAIL, timeout, etc.
        $dnsFailed++
        $err = ($_.Exception.Message -split "`n")[0].Trim()
        Write-Host ("  [DNS FAIL] {0,-45} {1}" -f $s, $err) -ForegroundColor DarkYellow
    }
}

Write-Host "`n$($live.Count) hosts resolve, $dnsFailed failed to resolve. Starting probe.`n" -ForegroundColor Cyan

$results = [System.Collections.Generic.List[object]]::new()
$total   = $live.Count
$i       = 0

foreach ($entry in $live) {
    $i++
    $h  = $entry.Host
    $ip = $entry.IP
    $ci = $certInfo[$h]   # cert issued/expiry dates for this host (may be $null)
    $pct = [int](($i / $total) * 100)
    Write-Progress -Activity "Probing hosts for PHP paths" `
                   -Status "[$i/$total] $h ($ip)  ($($total - $i) left)" `
                   -PercentComplete $pct

    foreach ($p in $paths) {
        try {
            $r = Invoke-WebRequest "https://$h$p" -Method Head -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
            if ($r.StatusCode -eq 200) {

                # ---------------------------- PHP signal extraction -----------------------------------
                $xpb    = $r.Headers["X-Powered-By"]
                $server = $r.Headers["Server"]
                $cookie = $r.Headers["Set-Cookie"]

                # PHP session cookie is a strong indicator even when X-Powered-By is stripped
                $phpSession = [bool]($cookie -match "PHPSESSID")

                # Pull a version string like "PHP/8.2.12" from either header
                $phpVersion = $null
                $verMatch = [regex]::Match("$xpb $server", 'PHP/([0-9]+\.[0-9]+(\.[0-9]+)?)')
                if ($verMatch.Success) { $phpVersion = $verMatch.Groups[1].Value }

                # Is PHP present at all, by any signal?
                $isPhp = [bool]($xpb -match "PHP") -or $phpSession -or ($null -ne $phpVersion)

                # Flag end-of-life major versions (5.x and 7.x are all past EOL)
                $eol = $false
                if ($phpVersion) {
                    $major = [int]($phpVersion -split '\.')[0]
                    if ($major -lt 8) { $eol = $true }
                }

                $hit = [pscustomobject]@{
                    Host       = $h
                    IP         = $ip
                    Path       = $p
                    Status     = 200
                    IsPHP      = $isPhp
                    PHPVersion = $phpVersion
                    EOL        = $eol
                    CertIssued  = if ($ci) { $ci.Issued }  else { "" }
                    CertExpires = if ($ci) { $ci.Expires } else { "" }
                    XPoweredBy = $xpb
                    PHPSESSID  = $phpSession
                    Server     = $server
                }
                $results.Add($hit)

                # Colour the hit line by confidence: red = EOL PHP, green = PHP, grey = 200 but no PHP signal
                $colour = if ($eol) { "Red" } elseif ($isPhp) { "Green" } else { "DarkGray" }
                $verTxt = if ($phpVersion) { "PHP $phpVersion" } elseif ($isPhp) { "PHP (ver hidden)" } else { "no PHP signal" }
                Write-Host ("  [HIT] {0,-40} {1,-16} {2,-18} {3}" -f $h, $ip, $p, $verTxt) -ForegroundColor $colour
            }
        } catch {}
        Start-Sleep -Milliseconds 150
    }
}

Write-Progress -Activity "Probing hosts for PHP paths" -Completed

$phpHosts = ($results | Where-Object { $_.IsPHP }).Host | Sort-Object -Unique
$eolHosts = ($results | Where-Object { $_.EOL }).Host | Sort-Object -Unique

Write-Host "`nDone." -ForegroundColor Cyan
Write-Host "  $($results.Count) total 200-responses across $(($results.Host | Sort-Object -Unique).Count) hosts."
Write-Host "  $($phpHosts.Count) hosts show a PHP signal."
if ($eolHosts.Count -gt 0) {
    Write-Host "  $($eolHosts.Count) hosts expose an END-OF-LIFE PHP version:" -ForegroundColor Red
    $eolHosts | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
}

$results | Format-Table Host,IP,Path,IsPHP,PHPVersion,EOL,CertIssued,CertExpires -AutoSize

# Stamp each run with the scan timestamp, storing it in a ScanTime column and in the filename so every output is uniquely saved.
$now       = Get-Date
$scanTime  = $now.ToString("yyyy-MM-dd HH:mm:ss")
$timestamp = $now.ToString("yyyy-MM-dd_HHmmss")
$outFile   = ".\php_vulnerability_candidate_$timestamp.csv"

$results |
    Select-Object @{Name='ScanTime';Expression={$scanTime}}, * |
    Export-Csv $outFile -NoTypeInformation

Write-Host "`nExported $($results.Count) rows to $outFile" -ForegroundColor Cyan