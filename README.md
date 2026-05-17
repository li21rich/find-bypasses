# find-bypasses

Automated recon pipeline for finding auth bypasses on any website domain

1. Enumerates subdomains with subfinder
2. Probes for 401/403 responses with httpx
3. Attempts header-based auth bypass (X-Forwarded-For, X-Remote-IP, etc.) using authslicer
4. Pulls historical URLs from Wayback Machine using waybackurls
5. Runs gf patterns to find interesting endpoints
6. Probes wayback URLs for 401/403 and attempts bypass on those too

### Setup
```
pip install -r requirements.txt
```
### Usage
```
python findbypasses.py targetwebsite.com
```
Results are saved to `targetwebsite_com/` in the same directory.

Only use against targets you are authorized to test, i.e. bugcrowd engagements.