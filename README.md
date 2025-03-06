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
