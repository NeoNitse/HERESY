#!/usr/bin/env python3
"""
██╗  ██╗███████╗██████╗ ███████╗███████╗██╗   ██╗
██║  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚██╗ ██╔╝
███████║█████╗  ██████╔╝█████╗  ███████╗ ╚████╔╝
██╔══██║██╔══╝  ██╔══██╗██╔══╝  ╚════██║  ╚██╔╝
██║  ██║███████╗██║  ██║███████╗███████║   ██║
╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝
v1.0 — Threat Intelligence Aggregator
"Nothing escapes judgment."
"""

import sys, os, re, json, time, argparse, ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("\n[!] Missing dependency. Run: pip install requests\n")
    sys.exit(1)

class C:
    R   = '\033[31m'
    BR  = '\033[91m'
    DR  = '\033[38;5;88m'
    OR  = '\033[38;5;202m'
    YW  = '\033[93m'
    GR  = '\033[32m'
    BGG = '\033[92m'
    CY  = '\033[36m'
    WH  = '\033[97m'
    GRY = '\033[38;5;240m'
    RS  = '\033[0m'
    BO  = '\033[1m'
    DIM = '\033[2m'

CONFIG_DIR  = os.path.expanduser('~/.config/heresy')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'config.json')

DEFAULT_CONFIG = {
    'abuseipdb':  '',
    'virustotal': '',
    'ipinfo':     '',
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return {**DEFAULT_CONFIG, **json.load(f)}
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)

def setup_wizard():
    clear()
    print(banner())
    print(f"\n{C.WH}  ╔══════════════════════════════════════╗")
    print(f"  ║        FIRST-TIME SETUP              ║")
    print(f"  ║  Configure your API keys to begin    ║")
    print(f"  ╚══════════════════════════════════════╝{C.RS}\n")

    print(f"  {C.GRY}Get your free API keys:{C.RS}")
    print(f"  {C.DR}▸{C.RS} AbuseIPDB  → {C.CY}https://www.abuseipdb.com/api{C.RS}")
    print(f"  {C.DR}▸{C.RS} VirusTotal → {C.CY}https://www.virustotal.com/gui/join-us{C.RS}")
    print(f"  {C.DR}▸{C.RS} IPInfo     → {C.CY}https://ipinfo.io/signup{C.RS} {C.GRY}(optional){C.RS}\n")

    cfg = load_config()
    for key, label, required in [
        ('abuseipdb',  'AbuseIPDB API key',  True),
        ('virustotal', 'VirusTotal API key',  True),
        ('ipinfo',     'IPInfo token',        False),
    ]:
        tag   = f"{C.YW}[required]{C.RS}" if required else f"{C.GRY}[optional]{C.RS}"
        current = f"{C.GRY}(current: {cfg[key][:8]}...){C.RS}" if cfg[key] else ''
        try:
            val = input(f"  {C.WH}{label}{C.RS} {tag} {current}: ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C.GRY}  Setup cancelled.{C.RS}\n")
            return
        if val:
            cfg[key] = val

    save_config(cfg)
    print(f"\n  {C.BGG}✓ Configuration saved to {CONFIG_FILE}{C.RS}\n")
    time.sleep(1)

def banner():
    return (
f"""{C.BO}{C.DR}
  ██╗  ██╗███████╗██████╗ ███████╗███████╗██╗   ██╗
  ██║  ██║██╔════╝██╔══██╗██╔════╝██╔════╝╚██╗ ██╔╝
  ███████║█████╗  ██████╔╝█████╗  ███████╗ ╚████╔╝
  ██╔══██║██╔══╝  ██╔══██╗██╔══╝  ╚════██║  ╚██╔╝
  ██║  ██║███████╗██║  ██║███████╗███████║   ██║
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝{C.RS}
{C.GRY}  ─────────────────────────────────────────────────
  Threat Intelligence Aggregator  •  v1.0
  "Nothing escapes judgment."
  ─────────────────────────────────────────────────{C.RS}"""
    )

def detect_type(target):
    t = target.strip()
    try:
        ipaddress.ip_address(t)
        return 'ip'
    except ValueError:
        pass
    if re.fullmatch(r'[a-f0-9]{32}',  t, re.I): return 'md5'
    if re.fullmatch(r'[a-f0-9]{40}',  t, re.I): return 'sha1'
    if re.fullmatch(r'[a-f0-9]{64}',  t, re.I): return 'sha256'
    if re.fullmatch(r'[^@\s]+@[^@\s]+\.[^@\s]+', t): return 'email'
    t2 = re.sub(r'^https?://', '', t).split('/')[0]
    return 'domain'

TYPE_LABELS = {
    'ip':     'IPv4/IPv6 Address',
    'md5':    'MD5 Hash',
    'sha1':   'SHA-1 Hash',
    'sha256': 'SHA-256 Hash',
    'email':  'Email Address',
    'domain': 'Domain / URL',
}

def api_abuseipdb(ip, key):
    if not key:
        return {'_skip': 'No API key — run heresy --setup'}
    try:
        r = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={'Key': key, 'Accept': 'application/json'},
            params={'ipAddress': ip, 'maxAgeInDays': 90},
            timeout=12, verify=False
        )
        d = r.json().get('data', {})
        return {
            'score':    d.get('abuseConfidenceScore', 0),
            'reports':  d.get('totalReports', 0),
            'country':  d.get('countryCode', '??'),
            'isp':      d.get('isp', 'Unknown'),
            'usage':    d.get('usageType', 'Unknown'),
            'tor':      d.get('isTor', False),
        }
    except Exception as e:
        return {'_error': str(e)}

def api_virustotal(target, ttype, key):
    if not key:
        return {'_skip': 'No API key — run heresy --setup'}
    try:
        endpoints = {
            'ip':     f'https://www.virustotal.com/api/v3/ip_addresses/{target}',
            'domain': f'https://www.virustotal.com/api/v3/domains/{target}',
            'md5':    f'https://www.virustotal.com/api/v3/files/{target}',
            'sha1':   f'https://www.virustotal.com/api/v3/files/{target}',
            'sha256': f'https://www.virustotal.com/api/v3/files/{target}',
        }
        url = endpoints.get(ttype)
        if not url:
            return {'_skip': f'Type "{ttype}" not supported'}

        r = requests.get(url, headers={'x-apikey': key}, timeout=12, verify=False)
        if r.status_code == 404:
            return {'_error': 'Not found in VirusTotal database'}
        if r.status_code == 429:
            return {'_error': 'Rate limit reached (4 req/min on free tier)'}
        r.raise_for_status()

        stats = r.json()['data']['attributes'].get('last_analysis_stats', {})
        total = sum(stats.values())
        return {
            'malicious':   stats.get('malicious', 0),
            'suspicious':  stats.get('suspicious', 0),
            'harmless':    stats.get('harmless', 0),
            'undetected':  stats.get('undetected', 0),
            'total':       total,
        }
    except Exception as e:
        return {'_error': str(e)}

def api_ipinfo(ip, token=''):
    try:
        url = f'https://ipinfo.io/{ip}/json'
        params = {'token': token} if token else {}
        r = requests.get(url, params=params, timeout=10, verify=False)
        d = r.json()
        if 'bogon' in d:
            return {'_error': 'Private/reserved IP address'}
        return {
            'city':     d.get('city',     'Unknown'),
            'region':   d.get('region',   'Unknown'),
            'country':  d.get('country',  '??'),
            'org':      d.get('org',      'Unknown'),
            'hostname': d.get('hostname', '—'),
            'timezone': d.get('timezone', 'Unknown'),
        }
    except Exception as e:
        return {'_error': str(e)}

def api_dns_lookup(domain):
    import socket
    try:
        clean = re.sub(r'^https?://', '', domain).split('/')[0]
        ip = socket.gethostbyname(clean)
        return {'resolved_ip': ip, 'hostname': clean}
    except Exception as e:
        return {'_error': str(e)}

def bar(value, total=100, width=20, fill='█', empty='░'):
    filled = round((value / max(total, 1)) * width)
    return f"{fill * filled}{C.GRY}{empty * (width - filled)}{C.RS}"

def section(title):
    w = 52
    line = f"{'─' * ((w - len(title) - 2) // 2)}"
    return f"\n  {C.DR}{line}{C.RS} {C.WH}{C.BO}{title}{C.RS} {C.DR}{line}{C.RS}"

def kv(label, value, color=None):
    color = color or C.WH
    label_str = f"{C.GRY}{label:<20}{C.RS}"
    return f"    {label_str}{color}{value}{C.RS}"

def render_results(target, ttype, results, cfg):
    now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

    print(f"\n  {C.GRY}{'─'*52}{C.RS}")
    print(f"  {C.GRY}TARGET  {C.RS}➤  {C.WH}{C.BO}{target}{C.RS}")
    print(f"  {C.GRY}TYPE    {C.RS}➤  {C.CY}{TYPE_LABELS.get(ttype, ttype)}{C.RS}")
    print(f"  {C.GRY}QUERY   {C.RS}➤  {C.GRY}{now}{C.RS}")
    print(f"  {C.GRY}{'─'*52}{C.RS}")

    threat_score = 0  # 0=clean, 1=suspicious, 2=malicious
    verdict_reasons = []

    if 'abuseipdb' in results:
        d = results['abuseipdb']
        print(section('ABUSEIPDB'))
        if '_error' in d:
            print(f"    {C.OR}⚠  {d['_error']}{C.RS}")
        elif '_skip' in d:
            print(f"    {C.GRY}○  {d['_skip']}{C.RS}")
        else:
            score = d['score']
            sc = C.BGG if score < 15 else (C.YW if score < 50 else C.BR)
            print(kv('Abuse Score',
                f"{sc}{score}/100{C.RS}  {sc}{bar(score)}{C.RS}"))
            print(kv('Total Reports', f"{d['reports']}"))
            print(kv('Country',       f"{d['country']}"))
            print(kv('ISP',           f"{d['isp']}"))
            print(kv('Usage Type',    f"{d['usage']}"))
            if d.get('tor'):
                print(kv('TOR Node', f"{C.BR}YES ⚠{C.RS}"))
            if score > 50:
                threat_score = max(threat_score, 2)
                verdict_reasons.append(f"AbuseIPDB: {score}% confidence of abuse")
            elif score > 10:
                threat_score = max(threat_score, 1)
                verdict_reasons.append(f"AbuseIPDB: {score}% suspicious activity")

    if 'virustotal' in results:
        d = results['virustotal']
        print(section('VIRUSTOTAL'))
        if '_error' in d:
            print(f"    {C.OR}⚠  {d['_error']}{C.RS}")
        elif '_skip' in d:
            print(f"    {C.GRY}○  {d['_skip']}{C.RS}")
        else:
            mal  = d['malicious']
            sus  = d['suspicious']
            tot  = d['total']
            rate = round((mal / max(tot, 1)) * 100)
            mc   = C.BGG if mal == 0 else (C.YW if mal <= 3 else C.BR)
            print(kv('Malicious',    f"{mc}{mal} / {tot} engines{C.RS}"))
            print(kv('Suspicious',   f"{C.YW if sus > 0 else C.GRY}{sus}{C.RS}"))
            print(kv('Harmless',     f"{d['harmless']}"))
            print(kv('Detection',    f"{mc}{bar(rate)}{C.RS}  {mc}{rate}%{C.RS}"))
            if mal > 5:
                threat_score = max(threat_score, 2)
                verdict_reasons.append(f"VirusTotal: {mal} engines flagged as malicious")
            elif mal > 0:
                threat_score = max(threat_score, 1)
                verdict_reasons.append(f"VirusTotal: {mal} engines flagged as suspicious")

    geo_key = 'ipinfo' if 'ipinfo' in results else 'dns'
    if geo_key in results:
        d = results[geo_key]
        print(section('GEOLOCATION / DNS'))
        if '_error' in d:
            print(f"    {C.OR}⚠  {d['_error']}{C.RS}")
        elif '_skip' in d:
            print(f"    {C.GRY}○  {d['_skip']}{C.RS}")
        else:
            for label, key in [
                ('City',          'city'),
                ('Region',        'region'),
                ('Country',       'country'),
                ('Organization',  'org'),
                ('Hostname',      'hostname'),
                ('Timezone',      'timezone'),
                ('Resolved IP',   'resolved_ip'),
            ]:
                if key in d:
                    print(kv(label, d[key]))

    verdicts = [
        (C.BGG, '███  CLEAN      ███', 'No threats detected across all sources.'),
        (C.YW,  '███  SUSPICIOUS ███', 'Possible threat — investigate further.'),
        (C.BR,  '███  MALICIOUS  ███', 'HIGH RISK — avoid interaction.'),
    ]
    vc, vt, vd = verdicts[threat_score]

    print(f"\n  {C.GRY}{'═'*52}{C.RS}")
    print(f"\n  {C.WH}{C.BO}  VERDICT  {C.RS}  {C.BO}{vc}{vt}{C.RS}")
    print(f"  {C.GRY}           {vd}{C.RS}")
    if verdict_reasons:
        for r in verdict_reasons:
            print(f"  {C.DR}           ▸ {C.GRY}{r}{C.RS}")
    print(f"\n  {C.GRY}{'═'*52}{C.RS}\n")

def clear():
    os.system('clear' if os.name != 'nt' else 'cls')

def animate_loading(target):
    frames = ['◐', '◓', '◑', '◒']
    steps = [
        'Identifying target type',
        'Querying AbuseIPDB',
        'Querying VirusTotal',
        'Fetching geolocation',
        'Calculating verdict',
    ]
    for i, step in enumerate(steps):
        sys.stdout.write(
            f"\r  {C.DR}{frames[i % 4]}{C.RS}  {C.GRY}{step}...{C.RS}     "
        )
        sys.stdout.flush()
        time.sleep(0.3)
    sys.stdout.write('\r' + ' ' * 60 + '\r')
    sys.stdout.flush()

def analyze(target, cfg):
    clear()
    print(banner())
    ttype = detect_type(target)

    print(f"\n  {C.DR}▸{C.RS} Analyzing {C.WH}{C.BO}{target}{C.RS} ...")

    tasks = {}
    with ThreadPoolExecutor(max_workers=4) as ex:
        if ttype == 'ip':
            tasks['abuseipdb'] = ex.submit(api_abuseipdb, target, cfg['abuseipdb'])
            tasks['virustotal'] = ex.submit(api_virustotal, target, ttype, cfg['virustotal'])
            tasks['ipinfo'] = ex.submit(api_ipinfo, target, cfg.get('ipinfo', ''))

        elif ttype == 'domain':
            tasks['virustotal'] = ex.submit(api_virustotal, target, ttype, cfg['virustotal'])
            tasks['dns'] = ex.submit(api_dns_lookup, target)

        elif ttype in ('md5', 'sha1', 'sha256'):
            tasks['virustotal'] = ex.submit(api_virustotal, target, ttype, cfg['virustotal'])

        elif ttype == 'email':
            domain = target.split('@')[1]
            tasks['dns'] = ex.submit(api_dns_lookup, domain)
            tasks['virustotal'] = ex.submit(api_virustotal, domain, 'domain', cfg['virustotal'])

        animate_loading(target)
        results = {k: f.result() for k, f in tasks.items()}

    render_results(target, ttype, results, cfg)

def main():
    parser = argparse.ArgumentParser(
        prog='heresy',
        description='HERESY — Threat Intelligence Aggregator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
examples:
  heresy 8.8.8.8
  heresy malware.example.com
  heresy d41d8cd98f00b204e9800998ecf8427e
  heresy --setup
        """
    )
    parser.add_argument('target', nargs='?', help='IP, domain, hash, or email to analyze')
    parser.add_argument('--setup', action='store_true', help='Configure API keys')
    parser.add_argument('--version', action='version', version='HERESY v1.0')

    args = parser.parse_args()
    cfg  = load_config()

    if args.setup:
        setup_wizard()
        return

    if not cfg['abuseipdb'] and not cfg['virustotal']:
        clear()
        print(banner())
        print(f"\n  {C.YW}⚠  No API keys configured.{C.RS}")
        print(f"  {C.GRY}Run {C.WH}heresy --setup{C.GRY} to add your keys.{C.RS}")
        print(f"  {C.GRY}Keys are free at abuseipdb.com and virustotal.com{C.RS}\n")
        try:
            ans = input(f"  {C.WH}Run setup now? [Y/n]: {C.RS}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print()
            return
        if ans != 'n':
            setup_wizard()
            cfg = load_config()

    if not args.target:
        clear()
        print(banner())
        print(f"\n  {C.GRY}Usage:{C.RS}  {C.WH}heresy <target>{C.RS}")
        print(f"  {C.GRY}Setup:{C.RS}  {C.WH}heresy --setup{C.RS}")
        print(f"\n  {C.GRY}Accepts: IP address, domain, MD5/SHA1/SHA256 hash, email{C.RS}\n")
        try:
            target = input(f"  {C.DR}➤{C.RS}  Enter target: {C.WH}").strip()
            print(C.RS, end='')
        except (KeyboardInterrupt, EOFError):
            print(f"\n{C.RS}")
            return
        if not target:
            return
    else:
        target = args.target

    try:
        analyze(target, cfg)
    except KeyboardInterrupt:
        print(f"\n\n  {C.GRY}Interrupted.{C.RS}\n")

if __name__ == '__main__':
    main()
