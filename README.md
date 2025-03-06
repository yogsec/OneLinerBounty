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


Got it! Here's the `README.md` file with just the content you shared:

```markdown
# OneLinerBounty

## Quick Bug Bounty Tips

Here are some essential one-liners for various bug bounty tasks:

### 1. Misconfigurations, Tech Detection, and Common Bugs
If you want wider coverage, like misconfigurations, tech detection, and common bugs, change the template path to `-t vulnerabilities/`:

```bash
cat urls.txt | httpx -silent -mc 200 | nuclei -silent -t vulnerabilities/ -o results.txt
```

### 2. Subdomain Takeovers - Quick Check
Want to check for subdomain takeovers in one line?

```bash
subfinder -d example.com | httpx -silent | nuclei -silent -t takeovers/ -o takeover.txt
```

### 3. Subdomain Discovery + Live Check
For subdomain discovery with live check:

```bash
subfinder -d target.com | httpx -silent -mc 200
```

### 4. Subdomain Takeover Detection
Detect subdomain takeovers:

```bash
subfinder -d target.com | httpx -silent | nuclei -silent -t takeovers/
```

### 5. Directory Bruteforce (Content Discovery)
For directory bruteforce:

```bash
ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -mc 200
```

### 6. Find Open Redirects (Quick Scan)
To quickly find open redirects:

```bash
cat urls.txt | gf redirect | httpx -silent
```

### 7. XSS Detection (Using Dalfox)
For XSS detection using Dalfox:

```bash
cat urls.txt | dalfox pipe --skip-bav --only-poc
```

### 8. SQL Injection Discovery
For SQL Injection discovery:

```bash
cat urls.txt | gf sqli | sqlmap --batch --random-agent -m -
```
```

You can add more content as you go. Let me know whenever you're ready for the next part!
