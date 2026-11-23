# Threat Intelligence Hub

A local React + FastAPI defensive threat-intelligence dashboard.

## Included live lookups

- **IP:** VirusTotal, AbuseIPDB, AlienVault OTX (if configured)
- **Domain:** VirusTotal, RDAP registration data, AlienVault OTX (if configured)
- **URL:** VirusTotal, existing urlscan.io search results, URLhaus, AlienVault OTX (if configured)
- **Hash / uploaded sample:** VirusTotal and MalwareBazaar hash lookups
- **CVE:** NIST NVD API 2.0
- **Phishing domain/email:** domain reputation lookups (email header parsing/authentication is not implemented)

A provider without a configured key is shown as **not configured**. Provider errors and rate limits are shown separately; the application does not invent results. A clean/no-match result is not a guarantee that an indicator is safe.

## Windows startup

1. Extract this folder.
2. Install Python 3.10+ and Node.js LTS if they are not already installed.
3. Double-click `start-threatintel.bat`.
4. On first launch, the script creates the Python virtual environment, installs dependencies, installs frontend packages, and starts the services.
5. Open `http://localhost:5173` if the browser does not open automatically.

Keep both terminal windows open while using the website. FastAPI uses port **8001**; the Vite frontend uses **5173**. This does not use Splunk's port 8000.

## Configure API keys

1. Open the `backend` folder.
2. Copy `.env.example` and rename the copy to `.env`.
3. Paste your own keys after the `=` signs in `.env`.
4. Save the file and restart the application.

Supported variables:

```ini
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
URLSCAN_API_KEY=
MALWAREBAZAAR_AUTH_KEY=
OTX_API_KEY=
NVD_API_KEY=
URLHAUS_AUTH_KEY=
```

Never paste keys into chat, `App.jsx`, or any frontend file. Do not share the `.env` file.

## Safety and limitations

- Uploaded files are hashed and stored in the local `backend/quarantine` folder. The sample itself is not sent to VirusTotal or MalwareBazaar; only its hash is queried.
- The app never executes uploaded files. Dynamic malware analysis is deliberately disabled and requires a separately isolated sandbox.
- URL lookups do not fetch or open the submitted URL. urlscan.io is queried for **existing indexed scans only**. The app does not automatically submit URLs because URLs may contain private tokens or personal information.
- WHO.IS is a website, not the source used here; domain registration information is retrieved through RDAP, the standardized successor to WHOIS for gTLD registration data.
- MXToolbox is not wired in this version because its API access/credentials depend on its service offering. DNS/MX/SPF/DMARC checks are not represented as completed.
- Threat Feeds, MITRE ATT&CK dataset browsing, and Cyber Threat News remain clearly marked as not configured/not included; they do not display fabricated intelligence.
- Free API plans have rate limits and provider terms. Use only indicators you are authorized to investigate and review each provider's terms.

## API documentation

- VirusTotal: https://docs.virustotal.com/reference/overview
- AbuseIPDB: https://docs.abuseipdb.com/
- urlscan.io: https://urlscan.io/docs/search/
- MalwareBazaar: https://bazaar.abuse.ch/api/
- NIST NVD: https://nvd.nist.gov/developers/vulnerabilities
- ICANN RDAP: https://www.icann.org/en/contracted-parties/registry-operators/registration-data-access-protocol
- AlienVault OTX: https://otx.alienvault.com/api
- URLhaus: https://urlhaus.abuse.ch/api/
