# PHPFinder
This script in a simple solution to checks for all active SSL certificates for your organization by exporting JSON data from crt.sh, resolves each host, and probes common PHP paths over HTTPS to detect PHP (via the X-Powered-By, Server, and PHPSESSID headers), flag end-of-life versions, and export the PHP-positive hosts to a CSV.
