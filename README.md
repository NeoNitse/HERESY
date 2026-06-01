<div align="center">

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0d0000,1a0000,880000&height=140&section=header&text=HERESY&fontSize=56&fontColor=cc0000&animation=fadeIn&fontAlignY=38&desc=nothing+escapes+judgment&descAlignY=68&descSize=14&descColor=550000"/>

[![Typing SVG](https://readme-typing-svg.demolab.com?font=Fira+Code&size=13&duration=3500&pause=1500&color=880000&center=true&vCenter=true&width=480&lines=Threat+Intelligence+Aggregator;AbuseIPDB+%C2%B7+VirusTotal+%C2%B7+IPInfo;Feed+it+a+target.+It+will+judge.;Nothing+escapes.)](https://git.io/typing-svg)

![Python](https://img.shields.io/badge/Python-0d0000?style=flat-square&logo=python&logoColor=cc0000)
![Platform](https://img.shields.io/badge/Platform-Linux%20%2F%20WSL-0d0000?style=flat-square&logoColor=cc0000)
![License](https://img.shields.io/badge/License-MIT-0d0000?style=flat-square&logoColor=cc0000)

</div>

---

Feed it an IP, a domain, a file hash. It consults the abyss — **AbuseIPDB**, **VirusTotal**, **IPInfo** — simultaneously. It returns a verdict.

`CLEAN` · `SUSPICIOUS` · `MALICIOUS`


---

## install

```bash
curl -sL https://raw.githubusercontent.com/NeoNitse/HERESY/main/heresy.py -o heresy.py
chmod +x heresy.py
pip install requests --break-system-packages -q
sudo mv heresy.py /usr/local/bin/heresy
```

---

## setup

```bash
heresy --setup
```

Get your free keys at:
- [abuseipdb.com/api](https://www.abuseipdb.com/api) — 1,000 checks/day
- [virustotal.com/gui/join-us](https://www.virustotal.com/gui/join-us) — 500/day
- [ipinfo.io/signup](https://ipinfo.io/signup) — 50k/month *(optional)*

---

## usage

```bash
# Analyze an IP
heresy 8.8.8.8

# Analyze a domain
heresy malware.wicar.org

# Analyze a file hash (MD5 / SHA1 / SHA256)
heresy 44d88612fea8a8f36de82e1278abb02f

# Reconfigure keys
heresy --setup
```

---

## verdict

```
  VERDICT     ███  MALICIOUS  ███
              HIGH RISK — avoid interaction.
              ▸ AbuseIPDB: 87% confidence of abuse
              ▸ VirusTotal: 34 engines flagged as malicious
```

---

<div align="center">

*Built on Kali GNU/Linux. Made in El Salvador 🇸🇻*

<img width="100%" src="https://capsule-render.vercel.app/api?type=waving&color=0d0000,1a0000,880000&height=80&section=footer"/>

</div>
