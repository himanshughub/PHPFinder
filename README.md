# PHPFinder Script
This script in a simple solution to checks for all active SSL certificates for your organization by exporting JSON data from crt.sh, resolves each host, and probes common PHP paths over HTTPS to detect PHP (via the X-Powered-By, Server, and PHPSESSID headers), flag end-of-life versions, and export the PHP-positive hosts to a CSV.

# How to Run?
Download the script on your machine and modify the 1st line in the script to add the domain which you would like to script to check certificates for.

```$root  = "<insert_the_domain_here>"```

for example:

```$root  = "xxxx.com"```

Once modified, run below command to execute in PowerShell:

```powershell -ExecutionPolicy Bypass -File .\phpfinder.ps1```

# Snapshot of Script Output:
![output_snap]()
