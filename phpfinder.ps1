param(
    [string]$Root,                    # prompt user to enter domain
    [int]$Throttle    = 15,           # hosts probed at once
    [int]$TimeoutSec  = 12,
    [switch]$DeepCheck                # also try headless browser on blocked endpoints (slower)
)

$paths = "/index.php","/wp-login.php","/xmlrpc.php","/administrator/"

# Minimum patched release per supported PHP branch. Anything below -> red, at/above -> green.
# Branches older than 8.2 are always red; branches newer than 8.5 are always green.
$PhpMinPatched = [ordered]@{
    '8.2' = [version]'8.2.35'
    '8.3' = [version]'8.3.36'
    '8.4' = [version]'8.4.27'
    '8.5' = [version]'8.5.12'
}

# Ask User for the domain
if (-not $Root) { $Root = Read-Host "Enter the domain to find PHP/WordPress hosts for (e.g. example.com)" }

$Root = $Root.Trim().ToLower().TrimStart('*','.')
if (-not $Root) { Write-Host "No domain entered." -ForegroundColor Red; return }

# Process-wide TLS + cert bypass. C# callback, because a PS scriptblock one fails on worker threads.
if ($PSVersionTable.PSVersion.Major -lt 7) {
    if (-not ('CertBypass' -as [type])) {
        Add-Type -TypeDefinition @"
using System.Net; using System.Net.Security; using System.Security.Cryptography.X509Certificates;
public static class CertBypass {
    public static bool Ok(object s, X509Certificate c, X509Chain h, SslPolicyErrors e) { return true; }
    public static void On() { ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(Ok); }
}
"@
    }
    [CertBypass]::On()
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls
    [Net.ServicePointManager]::DefaultConnectionLimit = 200
}
$isPS7 = $PSVersionTable.PSVersion.Major -ge 7

if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Host "Installing ImportExcel module (one-time)..." -ForegroundColor Yellow
    Install-Module ImportExcel -Scope CurrentUser -Force
}
Import-Module ImportExcel

$curlExe = Get-Command curl.exe -CommandType Application -ErrorAction SilentlyContinue |
           Select-Object -First 1 -ExpandProperty Source
$browserExe = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
    "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
    "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

# --- Input: active certs from crt.sh -----------------
$crtUrl = "https://crt.sh/?q=%25.$Root&output=json&exclude=expired"
Write-Host "Querying crt.sh for active certificates under '$Root'..." -ForegroundColor Cyan
$certs = $null
for ($try = 1; $try -le 4; $try++) {
    try { $certs = Invoke-RestMethod -Uri $crtUrl -TimeoutSec 180 -UserAgent "PHPFinder/2.0" -ErrorAction Stop; break }
    catch {
        $err = ($_.Exception.Message -split "`n")[0].Trim()
        if ($try -lt 4) { $w = 10 * $try; Write-Host "  attempt $try/4 failed: $err - retry in $w s" -ForegroundColor DarkYellow; Start-Sleep $w }
        else { Write-Host "crt.sh failed after 4 attempts: $err" -ForegroundColor Red; return }
    }
}
$certs = @($certs)
if (-not $certs -or -not $certs[0]) { Write-Host "crt.sh returned nothing for '$Root'." -ForegroundColor Red; return }
Write-Host "crt.sh returned $($certs.Count) certificate entries." -ForegroundColor Cyan

# Map each hostname to its longest-lived cert
$certInfo = @{}; $wild = 0
foreach ($c in $certs) {
    $expStr = "$($c.not_after)".Trim()
    [datetime]$exp = [datetime]::MinValue
    $expRaw = if ([datetime]::TryParse($expStr, [ref]$exp)) { $exp } else { [datetime]::MinValue }
    $issuerO = [regex]::Match("$($c.issuer_name)", '(?:^|,\s*)O=("?)([^,"]+)\1').Groups[2].Value
    if (-not $issuerO) { $issuerO = "$($c.issuer_name)" }
    foreach ($n in (@("$($c.name_value)" -split "`n") + "$($c.common_name)")) {
        $name = $n.Trim().ToLower()
        if (-not $name) { continue }
        if ($name.StartsWith("*.")) { $name = $name.Substring(2); $wild++ }   # wildcards -> base name
        if ($name -notmatch '^[a-z0-9.-]+$') { continue }
        if ($name -ne $Root -and -not $name.EndsWith(".$Root")) { continue }
        if (-not $certInfo.ContainsKey($name) -or $expRaw -gt $certInfo[$name].ExpiresRaw) {
            $certInfo[$name] = [pscustomobject]@{ Expires = $expStr; Issuer = $issuerO.Trim(); CrtShId = "$($c.id)"; ExpiresRaw = $expRaw }
        }
    }
}
$subs = $certInfo.Keys | Sort-Object -Unique
if (-not $subs) { Write-Host "No usable hostnames under '$Root'." -ForegroundColor Red; return }
Write-Host "Found $(@($subs).Count) unique hostnames ($wild wildcards collapsed). Probing...`n" -ForegroundColor Cyan

# --- Worker: resolve + probe one host ------------------------------------------
$worker = {
    param($TargetHost,$Paths,$CertExpires,$CertIssuer,$CrtShId,$TimeoutSec,$CurlExe,$BrowserExe,$DeepCheck,$IsPS7)

    $ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    $blocked = 401,403,406,429,503

    # Normalise any header collection (PS5 dictionary, PS7 dictionary, WebHeaderCollection,
    # HttpResponseHeaders) into one case-insensitive hashtable of name -> "value[, value...]"
    function ConvertTo-HeaderMap($h) {
        $m = @{}
        if (-not $h) { return $m }
        if ($h -is [System.Collections.IDictionary]) {
            foreach ($k in $h.Keys) { $m["$k"] = (@($h[$k]) -join ', ') }
        }
        elseif ($h.PSObject.Properties['AllKeys']) {                      # WebHeaderCollection (PS5 error responses)
            foreach ($k in $h.AllKeys) { $m["$k"] = "$($h[$k])" }
        }
        else {                                                             # HttpResponseHeaders (PS7 error responses)
            foreach ($kv in $h) { if ($kv.Key) { $m["$($kv.Key)"] = (@($kv.Value) -join ', ') } }
        }
        return $m
    }

    # Parse the final response's headers out of a curl -D dump (handles redirect chains)
    function Read-CurlHeaders($File) {
        $m = @{}
        if (-not (Test-Path $File)) { return $m }
        $raw = Get-Content $File -Raw -ErrorAction SilentlyContinue
        if (-not $raw) { return $m }
        $blocks = @(($raw -split "\r?\n\r?\n") | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^HTTP/' })
        if (-not $blocks) { return $m }
        foreach ($line in (($blocks[-1] -split "\r?\n") | Select-Object -Skip 1)) {
            $i = $line.IndexOf(':'); if ($i -lt 1) { continue }
            $k = $line.Substring(0,$i).Trim(); $v = $line.Substring($i+1).Trim()
            if ($m.ContainsKey($k)) { $m[$k] = "$($m[$k]), $v" } else { $m[$k] = $v }
        }
        return $m
    }

    # One GET; keeps the body AND headers of error responses (xmlrpc answers a GET with 405)
    function Get-PS($Url) {
        $p = @{ Uri=$Url; UseBasicParsing=$true; UserAgent=$ua; TimeoutSec=$TimeoutSec; MaximumRedirection=10; ErrorAction='Stop' }
        if ($IsPS7) { $p.SkipCertificateCheck = $true }
        try { $r = Invoke-WebRequest @p; return @{ Status=[int]$r.StatusCode; Body=$r.Content; Headers=(ConvertTo-HeaderMap $r.Headers); Error=$null } }
        catch {
            $st=$null; $body=$null; $hdrs=$null; $resp=$_.Exception.Response
            if ($resp) { try { $st=[int]$resp.StatusCode } catch {}; try { $hdrs=ConvertTo-HeaderMap $resp.Headers } catch {} }
            if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $body=$_.ErrorDetails.Message }
            elseif ($resp -is [System.Net.HttpWebResponse]) { try { $body=(New-Object System.IO.StreamReader($resp.GetResponseStream())).ReadToEnd() } catch {} }
            if ($st) { return @{ Status=$st; Body=$body; Headers=$hdrs; Error=$null } }
            return @{ Status=$null; Body=$null; Headers=$null; Error="connection failed" }
        }
    }
    # curl.exe fallback for WAF-blocked endpoints (now also captures response headers)
    function Get-Curl($Url) {
        $tmp=[IO.Path]::GetTempFileName(); $hdr=[IO.Path]::GetTempFileName()
        try {
            $code = & $CurlExe -s -k -L --compressed --ssl-no-revoke --max-redirs 10 --connect-timeout 8 --max-time $TimeoutSec -A $ua -D $hdr -o $tmp -w "%{http_code}" $Url 2>$null
            if ($code -match '^\d{3}$' -and $code -ne '000') {
                return @{ Status=[int]$code; Body=(Get-Content $tmp -Raw -Encoding UTF8); Headers=(Read-CurlHeaders $hdr); Error=$null }
            }
            return @{ Status=$null; Body=$null; Headers=$null; Error="connection failed" }
        } finally { Remove-Item $tmp,$hdr -ErrorAction SilentlyContinue }
    }
    # Headless browser: last resort in case GET or curl failed
    function Get-Browser($Url) {
        $tmp=[IO.Path]::GetTempFileName(); $prof=Join-Path $env:TEMP ("phpf-"+[guid]::NewGuid().ToString("N"))
        try {
            $a=@("--headless=new","--disable-gpu","--no-first-run","--no-default-browser-check","--ignore-certificate-errors","--virtual-time-budget=8000","--user-data-dir=`"$prof`"","--dump-dom",$Url)
            $pr=Start-Process -FilePath $BrowserExe -ArgumentList $a -PassThru -WindowStyle Hidden -RedirectStandardOutput $tmp
            if (-not $pr.WaitForExit(($TimeoutSec+10)*1000)) { try{$pr.Kill()}catch{}; return @{ Status=$null; Body=$null; Headers=$null; Error="timed out" } }
            return @{ Status=$null; Body=(Get-Content $tmp -Raw -Encoding UTF8); Headers=$null; Error=$null }
        } finally { Remove-Item $tmp -ErrorAction SilentlyContinue; Remove-Item $prof -Recurse -Force -ErrorAction SilentlyContinue }
    }
    # GET with escalation when blocked
    function Fetch($Url) {
        $pg = Get-PS $Url
        if (($pg.Error -or $blocked -contains $pg.Status) -and $CurlExe) { $c=Get-Curl $Url; if ($c.Status -or $c.Body) { $pg=$c } }
        if ($DeepCheck -and ($pg.Error -or $blocked -contains $pg.Status) -and $BrowserExe) { $b=Get-Browser $Url; if ($b.Body) { $pg=$b } }
        return $pg
    }
    # Case/whitespace-insensitive text search
    function Has($Body,$Text) { if (-not $Body) { return $false }; $c=($Body -replace '&nbsp;|&#160;|\u00A0',' ') -replace '\s+',' '; return ($c.IndexOf($Text,[StringComparison]::OrdinalIgnoreCase) -ge 0) }
    # Header lookup (headers are always a case-insensitive hashtable now)
    function GetH($h,$n) { if (-not $h) { return $null }; $v=$h[$n]; if ($null -eq $v) { return $null }; return ((@($v) -join ', ').Trim()) }

    # Resolve first; skip hosts with no A record
    $ip=$null
    try { $d=Resolve-DnsName $TargetHost -Type A -ErrorAction Stop | Where-Object {$_.IPAddress} | Select-Object -First 1; if ($d) { $ip=$d.IPAddress } } catch {}
    if (-not $ip) { return [pscustomobject]@{ Host=$TargetHost; Include=$false; Note=""; Color=""; Status="dns-fail" } }

    $phpVer=$null; $isPhp=$false; $eol=$false; $wpSig=@(); $p200=@(); $wpExp=$false; $xmlExp=$false
    foreach ($p in $Paths) {
        $pg=Fetch "https://$TargetHost$p"; $body=$pg.Body; $hdrs=$pg.Headers; $st=$pg.Status

        if ($p -eq '/wp-login.php' -and ((Has $body 'Username or Email Address') -or (Has $body 'Sign in to your site'))) { $wpExp=$true }
        if ($p -eq '/xmlrpc.php'   -and  (Has $body 'XML-RPC server accepts POST requests only')) { $xmlExp=$true }
        if ($st -eq 200) { $p200 += $p }

        # PHP / WordPress signals from headers (record header NAME + VALUE)
        $xpb=GetH $hdrs 'X-Powered-By'; $server=GetH $hdrs 'Server'; $cookie=GetH $hdrs 'Set-Cookie'
        if ($cookie -match 'PHPSESSID') { $isPhp=$true }
        $vm=[regex]::Match("$xpb $server",'PHP/([0-9]+\.[0-9]+(\.[0-9]+)?)'); if ($vm.Success) { $phpVer=$vm.Groups[1].Value; $isPhp=$true }
        if ($xpb -match 'PHP') { $isPhp=$true }
        if ($xpb -match 'WP Engine|W3 Total Cache|WordPress') { $wpSig+="X-Powered-By: $xpb" }
        $pingback = GetH $hdrs 'X-Pingback'; if ($pingback) { $wpSig+="X-Pingback: $pingback" }
        if ((GetH $hdrs 'Link') -match 'api\.w\.org|/wp-json') { $wpSig+="wp-json" }
        if ($cookie -match 'wordpress|wp-settings|wp_') { $wpSig+="WP-Cookie" }
        foreach ($hd in 'X-Kinsta-Cache','X-LiteSpeed-Cache','X-Hacker','X-ac') { $hv=GetH $hdrs $hd; if ($hv) { $wpSig+="${hd}: $hv" } }
        if ($server -match 'WP Engine|Flywheel|Pressable') { $wpSig+="Server: $server" }
        Start-Sleep -Milliseconds 100
    }

    # Exposed endpoints are themselves WordPress proof
    if ($wpExp)  { $wpSig+="wp-login" }
    if ($xmlExp) { $wpSig+="xmlrpc" }
    $isWP = ($wpSig.Count -gt 0)
    if ($isWP) { $isPhp=$true }
    if ($phpVer) { if ([int](($phpVer -split '\.')[0]) -lt 8) { $eol=$true } }   # PHP 5.x/7.x are EOL

    # Note + colour by priority (EOL worst, clean "looks good" best)
    if     ($eol)               { $note="Running on EOL/Vulnerable version of PHP"; $color="Red";    $pr=1 }
    elseif ($wpExp -and $xmlExp){ $note="wp-login.php not behind MFA, susceptible to Bruteforce attack; xmlrpc.php service is running, need to be blocked."; $color="Blue"; $pr=3 }
    elseif ($xmlExp)            { $note="xmlrpc.php service is running, need to be blocked."; $color="Orange"; $pr=2 }
    elseif ($wpExp)             { $note="wp-login.php not behind MFA, susceptible to Bruteforce attack"; $color="Yellow"; $pr=4 }
    elseif ($isWP)              { $note="wp-login.php and xmlrpc.php is blocked, looks good"; $color="Green"; $pr=5 }
    else                        { $note=""; $color=""; $pr=6 }

    return [pscustomobject]@{
        Host=$TargetHost; IP=$ip; Note=$note; Color=$color; Priority=$pr
        PHPVersion=$phpVer; EOL=$eol; IsWP=$isWP; WPLoginExposed=$wpExp; XmlrpcExposed=$xmlExp
        WPSignal=(($wpSig | Sort-Object -Unique) -join '; '); Paths200=($p200 -join ' ')
        CertExpires=$CertExpires; CertIssuer=$CertIssuer; CrtShId=$CrtShId
        Include=($note -ne ''); Status=$(if ($note) { $color } else { 'no-finding' })
    }
}

# --- Run probes in parallel ----------------------------------------------------
$pool = [RunspaceFactory]::CreateRunspacePool(1, $Throttle); $pool.Open()
$jobs = foreach ($h in $subs) {
    $ci = $certInfo[$h]
    $ps = [PowerShell]::Create(); $ps.RunspacePool = $pool
    [void]$ps.AddScript($worker).AddParameters(@{
        TargetHost=$h; Paths=$paths; CertExpires=$ci.Expires; CertIssuer=$ci.Issuer; CrtShId=$ci.CrtShId
        TimeoutSec=$TimeoutSec; CurlExe=$curlExe; BrowserExe=$browserExe; DeepCheck=[bool]$DeepCheck; IsPS7=$isPS7
    })
    [pscustomobject]@{ PS=$ps; Handle=$ps.BeginInvoke(); Done=$false }
}

$all=New-Object System.Collections.Generic.List[object]; $total=$jobs.Count; $seen=0; $start=Get-Date
$consoleColor=@{ Red='Red'; Orange='DarkYellow'; Blue='Blue'; Yellow='Yellow'; Green='Green' }
while ($seen -lt $total) {
    foreach ($j in $jobs) {
        if (-not $j.Done -and $j.Handle.IsCompleted) {
            $j.Done=$true; $seen++
            try {
                $r=$j.PS.EndInvoke($j.Handle)[0]; $all.Add($r)
                if ($r.Include) {
                    Write-Host ("[{0,-6}] {1,-40} {2}" -f $r.Color,$r.Host,$r.Note) -ForegroundColor $consoleColor[$r.Color]
                }
            } catch { }
            $j.PS.Dispose()
        }
    }
    Write-Progress -Activity "Probing hosts" -Status "$seen of $total done" -PercentComplete (($seen/[math]::Max($total,1))*100)
    Start-Sleep -Milliseconds 200
}
Write-Progress -Activity "Probing hosts" -Completed
$pool.Close(); $pool.Dispose()

# --- PHP version check against minimum patched releases -------------------------
# Returns $true (patched -> green), $false (outdated -> red), $null (no version -> no fill)
function Test-PhpPatched([string]$Ver) {
    if (-not $Ver) { return $null }
    $parts = $Ver.Trim() -split '\.'
    $maj = [int]$parts[0]
    $min = if ($parts.Count -gt 1) { [int]$parts[1] } else { 0 }
    $pat = if ($parts.Count -gt 2) { [int]$parts[2] } else { -1 }   # patch not disclosed
    $branch = "$maj.$min"
    if ($PhpMinPatched.Contains($branch)) {
        if ($pat -lt 0) { return $false }                               # can't confirm patch level -> treat as outdated
        return ([version]"$maj.$min.$pat" -ge $PhpMinPatched[$branch])
    }
    $oldest = [version](@($PhpMinPatched.Keys)[0])
    if ([version]$branch -lt $oldest) { return $false }                 # 8.1 and older (incl. 5.x/7.x)
    return $true                                                         # newer branch than listed (8.6+, 9.x)
}

# --- Output --------------------------------------------------------------------
$now=Get-Date; $scanTime=$now.ToString("yyyy-MM-dd HH:mm:ss"); $stamp=$now.ToString("yyyy-MM-dd_HHmmss")
$found = @($all | Where-Object { $_.Include } | Sort-Object Priority,Host)
$display = $found | Select-Object `
    Note,Host,IP,PHPVersion,EOL,IsWP,WPLoginExposed,XmlrpcExposed,WPSignal,Paths200,CertExpires,CertIssuer,CrtShId,
    @{N='ScanTime';E={$scanTime}},@{N='RootDomain';E={$Root}}

$xlsx=".\php_exposure_$($Root)_$stamp.xlsx"

if ($display) {
    # Palette: bg RGB + font RGB for contrast
    $fill=@{ Red=@(192,0,0,255,255,255); Orange=@(237,125,49,0,0,0); Blue=@(46,117,182,255,255,255); Yellow=@(255,217,102,0,0,0); Green=@(112,173,71,255,255,255) }
    function Set-CellColor($Cell,$Rgb) {
        $Cell.Style.Fill.PatternType=[OfficeOpenXml.Style.ExcelFillStyle]::Solid
        $Cell.Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::FromArgb(255,$Rgb[0],$Rgb[1],$Rgb[2]))
        $Cell.Style.Font.Color.SetColor([System.Drawing.Color]::FromArgb(255,$Rgb[3],$Rgb[4],$Rgb[5]))
    }

    # -NoNumberConversion keeps "8.2.35"/"8.10" as text (otherwise "8.10" would become 8.1)
    $pkg=$display | Export-Excel -Path $xlsx -WorksheetName 'PHP Findings' -AutoSize -FreezeTopRow -BoldTopRow -NoNumberConversion PHPVersion -PassThru
    $ws=$pkg.Workbook.Worksheets['PHP Findings']
    $cols=@(@($display)[0].PSObject.Properties.Name)
    $phpCol=[array]::IndexOf($cols,'PHPVersion') + 1

    for ($i=0; $i -lt $found.Count; $i++) {
        $row=$i+2

        # Note cell coloured by finding priority
        $m=$fill[$found[$i].Color]
        if ($m) { $cell=$ws.Cells[$row,1]; Set-CellColor $cell $m; $cell.Style.WrapText=$true }

        # PHPVersion cell: red if below minimum patched release for its branch, green otherwise
        if ($phpCol -gt 0) {
            $ok = Test-PhpPatched $found[$i].PHPVersion
            if ($ok -eq $true)      { Set-CellColor $ws.Cells[$row,$phpCol] $fill.Green }
            elseif ($ok -eq $false) { Set-CellColor $ws.Cells[$row,$phpCol] $fill.Red }
        }
    }
    $ws.Column(1).Width=60
    Close-ExcelPackage $pkg
}

# --- Summary -------------------------------------------------------------------
$by={ param($c) @($all | Where-Object { $_.Color -eq $c }).Count }
$dns=@($all | Where-Object { $_.Status -eq 'dns-fail' }).Count
$phpOld=@($found | Where-Object { (Test-PhpPatched $_.PHPVersion) -eq $false }).Count
$elapsed=[math]::Round(((Get-Date)-$start).TotalSeconds)
Write-Host "`nDone in $elapsed s. $($subs.Count) hosts, $dns DNS failures." -ForegroundColor Cyan
Write-Host ("  Red (EOL PHP):            {0}" -f (& $by 'Red'))    -ForegroundColor Red
Write-Host ("  Orange (xmlrpc only):     {0}" -f (& $by 'Orange')) -ForegroundColor DarkYellow
Write-Host ("  Blue (wp-login+xmlrpc):   {0}" -f (& $by 'Blue'))   -ForegroundColor Blue
Write-Host ("  Yellow (wp-login only):   {0}" -f (& $by 'Yellow')) -ForegroundColor Yellow
Write-Host ("  Green (blocked, good):    {0}" -f (& $by 'Green'))  -ForegroundColor Green
Write-Host ("  PHP below patched build:  {0}" -f $phpOld)          -ForegroundColor Red
if ($display) { Write-Host "`nSaved $(@($found).Count) findings to:`n  $xlsx" -ForegroundColor Cyan }
else          { Write-Host "`nNo findings to report." -ForegroundColor Green }
