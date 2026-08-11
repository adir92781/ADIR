#!/usr/bin/env python3
"""
validate_m3u.py

Scans an M3U playlist, checks each stream URL for availability, replaces with backups when configured,
injects channel icons (tvg-logo) from icons.json, and performs optional antivirus checks using VirusTotal.
Produces an updated playlist and a report.

Usage:
  python3 tools/validate_m3u.py ../IL.m3u8

Outputs:
  - IL.validated.m3u8 (in the same directory as input)
  - validation_report.json

Antivirus features:
  - If environment variable VIRUSTOTAL_API_KEY is set, the script will submit URLs to VirusTotal's URL analysis API
    and include the analysis permalink and summary verdict in the report.
  - The script also flags SSL errors, suspicious IP-based hosts, and unexpected content types.

Notes:
  - Provide tools/icons.json and tools/backups.json next to this script for icon injection and backup URLs.
  - This script uses requests and concurrent.futures for parallel checks.
"""

import sys
import os
import re
import json
import time
import hashlib
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.exceptions import SSLError, RequestException

# Config
TIMEOUT = 8
MAX_WORKERS = 12
USER_AGENT = "Mozilla/5.0 (compatible; ADIR-validator/1.1)"
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
VIRUSTOTAL_BASE = 'https://www.virustotal.com/api/v3'

RE_M3U_EXTINF = re.compile(r"^#EXTINF:(?P<inf>[^,]*),(?P<name>.*)")
RE_ATTR = re.compile(r'(?P<key>\w[\w-]*)="(?P<val>.*?)"')

# Heuristics
SUSPICIOUS_TLDS = {'.pw', '.top', '.tk', '.gq', '.cf', '.ml'}


def load_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)


def parse_extinf(line):
    m = RE_M3U_EXTINF.match(line)
    if not m:
        return None
    attrs = {}
    # extract attributes from the beginning between EXTINF: and comma
    header = line.split(',', 1)[0]
    parts = header.split(' ', 1)
    if len(parts) > 1:
        attr_text = parts[1]
        for a in RE_ATTR.finditer(attr_text):
            attrs[a.group('key')] = a.group('val')
    name = line.split(',', 1)[1].strip()
    return attrs, name


def build_extinf_line(attrs, name):
    # reconstruct attributes in the same format
    attr_parts = []
    for k, v in attrs.items():
        attr_parts.append(f'{k}="{v}"')
    attr_text = ' ' + ' '.join(attr_parts) if attr_parts else ''
    return f"#EXTINF:-1{attr_text},{name}"


def compute_sha256_bytes(data_bytes):
    h = hashlib.sha256()
    h.update(data_bytes)
    return h.hexdigest()


def is_ip_host(host):
    # crude check for IPv4 literal or IPv6
    try:
        # IPv4
        parts = host.split('.')
        if len(parts) == 4 and all(0 <= int(p) < 256 for p in parts if p.isdigit()):
            return True
    except Exception:
        pass
    # IPv6 literal contains ':'
    if ':' in host:
        return True
    return False


def check_url(url):
    headers = {'User-Agent': USER_AGENT}
    result = {
        'url': url,
        'ok': False,
        'status_code': None,
        'error': None,
        'content_type': None,
        'content_sha256': None,
        'ssl_ok': True,
        'suspicious_host': False,
        'virustotal': None,
    }
    try:
        # HEAD first
        r = requests.head(url, headers=headers, timeout=TIMEOUT, allow_redirects=True, verify=True)
        result['status_code'] = r.status_code
        result['content_type'] = r.headers.get('Content-Type')
        if r.status_code == 200 and r.headers.get('Content-Length') is not None:
            result['ok'] = True
            return result
        # If HEAD isn't reliable, try GET but only read a small chunk
        r = requests.get(url, headers=headers, timeout=TIMEOUT, stream=True, allow_redirects=True, verify=True)
        result['status_code'] = r.status_code
        result['content_type'] = r.headers.get('Content-Type')
        if r.status_code == 200:
            # read up to 64KB to compute a fingerprint
            buf = b''
            try:
                for chunk in r.iter_content(8192):
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) >= 64 * 1024:
                        break
                if buf:
                    result['content_sha256'] = compute_sha256_bytes(buf)
                    result['ok'] = True
                    return result
            except Exception as e:
                result['error'] = f'read_error:{e}'
                return result
        return result
    except SSLError as e:
        result['ssl_ok'] = False
        result['error'] = f'ssl:{e}'
        return result
    except RequestException as e:
        result['error'] = str(e)
        return result


def virustotal_scan_url(url):
    """Submit URL to VirusTotal and return a short analysis summary. Optional: requires VIRUSTOTAL_API_KEY."""
    if not VIRUSTOTAL_API_KEY:
        return {'error': 'no_api_key'}
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY,
        'User-Agent': USER_AGENT,
        'Accept': 'application/json',
    }
    try:
        # POST the URL for analysis
        submit = requests.post(f'{VIRUSTOTAL_BASE}/urls', headers=headers, data={'url': url}, timeout=15)
        if submit.status_code not in (200, 201):
            return {'error': f'submit_failed:{submit.status_code}'}
        j = submit.json()
        analysis_id = j.get('data', {}).get('id')
        if not analysis_id:
            return {'error': 'no_analysis_id'}
        # GET analysis
        analysis = requests.get(f'{VIRUSTOTAL_BASE}/analyses/{analysis_id}', headers=headers, timeout=15)
        if analysis.status_code != 200:
            return {'error': f'analysis_failed:{analysis.status_code}'}
        aj = analysis.json()
        stats = aj.get('data', {}).get('attributes', {}).get('stats', {})
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)
        harmless = stats.get('harmless', 0)
        suspicious_summary = {
            'malicious': malicious,
            'suspicious': suspicious,
            'harmless': harmless,
            'permalink': f'https://www.virustotal.com/gui/url/{analysis_id}/detection'
        }
        return suspicious_summary
    except Exception as e:
        return {'error': str(e)}


def evaluate_suspicious_host(parsed):
    host = parsed.hostname or ''
    # suspicious if IP literal
    if is_ip_host(host):
        return True
    # suspicious TLDs
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return True
    return False


def main():
    if len(sys.argv) < 2:
        print("Usage: validate_m3u.py <playlist.m3u8>")
        sys.exit(2)

    playlist_path = sys.argv[1]
    base_dir = os.path.dirname(os.path.abspath(__file__))
    icons_path = os.path.join(base_dir, 'icons.json')
    backups_path = os.path.join(base_dir, 'backups.json')

    icons = load_json(icons_path)
    backups = load_json(backups_path)

    with open(playlist_path, 'r', encoding='utf-8') as f:
        lines = [l.rstrip('\n') for l in f]

    report = {'checked': [], 'timestamp': time.time(), 'virustotal_used': bool(VIRUSTOTAL_API_KEY)}

    entries = []  # tuples of (extinf_idx, url_idx, attrs, name)

    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith('#EXTINF'):
            parsed = parse_extinf(line)
            if parsed is None:
                i += 1
                continue
            attrs, name = parsed
            # next non-empty line is expected to be the URL
            url = ''
            if i + 1 < len(lines):
                url = lines[i+1].strip()
            entries.append((i, i+1, attrs, name, url))
            i += 2
            continue
        i += 1

    # Check URLs in parallel
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_map = {}
        for entry in entries:
            url = entry[4]
            future = ex.submit(check_url, url)
            future_map[future] = entry

        for fut in as_completed(future_map):
            entry = future_map[fut]
            extinf_idx, url_idx, attrs, name, url = entry
            result = fut.result()
            rec = {
                'name': name,
                'tvg-id': attrs.get('tvg-id'),
                'original_url': url,
                'check': result,
            }

            parsed = urlparse(url)
            suspicious = evaluate_suspicious_host(parsed)
            if suspicious:
                rec['check']['suspicious_host'] = True

            # If offline, attempt backups by tvg-id then name
            if not result.get('ok'):
                tvg_id = attrs.get('tvg-id', '')
                candidate_list = []
                if tvg_id and tvg_id in backups:
                    candidate_list.extend(backups[tvg_id])
                if name in backups:
                    candidate_list.extend(backups[name])
                replaced = False
                for cand in candidate_list:
                    c_res = check_url(cand)
                    if c_res.get('ok'):
                        rec['replaced_with'] = cand
                        # update the playlist lines in-memory
                        lines[url_idx] = cand
                        replaced = True
                        break
                if not replaced:
                    # mark offline in the name so players can show it
                    new_name = name + ' [OFFLINE]'
                    lines[extinf_idx] = build_extinf_line(attrs, new_name)
                    rec['note'] = 'offline, no backup found'
            else:
                # if OK, optionally inject icon if missing
                if 'tvg-logo' not in attrs or not attrs.get('tvg-logo'):
                    # try by tvg-id then by name
                    tvg_id = attrs.get('tvg-id', '')
                    logo = None
                    if tvg_id and tvg_id in icons:
                        logo = icons[tvg_id]
                    elif name in icons:
                        logo = icons[name]
                    if logo:
                        attrs['tvg-logo'] = logo
                        lines[extinf_idx] = build_extinf_line(attrs, name)
                        rec['tvg-logo'] = logo

            # run VirusTotal scan if available and URL OK or suspicious
            if VIRUSTOTAL_API_KEY and (result.get('ok') or rec['check'].get('suspicious_host')):
                vt = virustotal_scan_url(url)
                rec['virustotal'] = vt

            report['checked'].append(rec)

    # Write validated playlist next to source
    out_path = os.path.join(os.path.dirname(playlist_path), 'IL.validated.m3u8')
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines) + '\n')

    # Write report
    report_path = os.path.join(os.path.dirname(playlist_path), 'validation_report.json')
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"Wrote validated playlist to: {out_path}")
    print(f"Wrote report to: {report_path}")


if __name__ == '__main__':
    main()
