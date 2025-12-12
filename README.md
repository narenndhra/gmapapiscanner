# Google Maps API Key Vulnerability Scanner

A fast, concurrency-enabled scanner for assessing Google Maps API keys against all major Google Maps Platform endpoints.  
Provides a clear **VULNERABLE / SECURE / UNDETERMINED** report with a modern **Rich-powered colored table UI**.

Ideal for developers, bug bounty researchers, and security testers.

---

## 1. Features

- Full coverage of major Google Maps APIs:
  - Geocoding
  - Reverse Geocoding
  - Directions
  - Distance Matrix
  - Elevation
  - Timezone
  - Static Maps
  - Street View
  - Places API (Text Search, Nearby Search, Details, Autocomplete)
  - Geolocation
  - Roads API (Nearest Roads, Speed Limits)
  - Embed (Basic + Advanced)
  - Playable Locations API
  - And more…

- **ThreadPoolExecutor concurrency** (up to 5× faster scans)
- Clean, colorful console UI using **rich**
- Automatic detection of:
  - Key misuse
  - Unrestricted APIs
  - Misconfigured restrictions
  - Disabled/unused APIs
  - HTML/error fallback handling
- Single-file scanner (`gmaps_scanner.py`)
- No API-abusive behavior; standard safe endpoint checks only

---

## 2. Requirements

### **Python Version**
- Python **3.9+** recommended  
- Tested on **Python 3.11**

### **Python Packages**
Install via `pip`:

```bash
pip install -r requirements.txt
````

or manually:

```bash
pip install requests rich
```

### **requirements.txt**

```
requests
rich
```

(If screenshot output is later enabled, additional modules will be added.)

---

## 3. Installation

Clone the repository:

```bash
git clone https://github.com/<your-username>/gmaps-api-scanner.git
cd gmaps-api-scanner
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Verify installation:

```bash
python3 gmaps_scanner.py --help
```

---

## 4. Usage

### **Basic Scan**

```bash
python3 gmaps_scanner.py --key YOUR_GOOGLE_MAPS_API_KEY
```

### **Custom Timeout**

```bash
python3 gmaps_scanner.py --key YOUR_KEY --timeout 12
```

### **Increase Workers (Faster Scan)**

```bash
python3 gmaps_scanner.py --key YOUR_KEY --workers 20
```

### **Save Raw JSON Output**

```bash
python3 gmaps_scanner.py --key YOUR_KEY --json result.json
```

### **Save CSV Report**

```bash
python3 gmaps_scanner.py --key YOUR_KEY --csv result.csv
```

---

## 5. Example Output

```
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ API                   ┃ Status       ┃ HTTP ┃ Reason                                               ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Geocode API           │ VULNERABLE   │ 200  │ 200 OK with real data                                 │
│ Staticmap API         │ SECURE       │ 403  │ Not authorized                                         │
│ Directions API        │ VULNERABLE   │ 200  │ 200 OK with real data                                 │
│ Places Details API    │ UNDETERMINED │ 200  │ Unknown JSON structure                                 │
│ Roads API             │ SECURE       │ 403  │ API not enabled                                        │
└───────────────────────┴──────────────┴──────┴────────────────────────────────────────────────────────┘
```

---

## 6. Supported APIs

The scanner currently tests and evaluates:

| Category                  | APIs                                              |
| ------------------------- | ------------------------------------------------- |
| **Maps Core**             | Geocoding, Reverse Geocoding, Timezone, Elevation |
| **Routes**                | Directions API, Distance Matrix API               |
| **Places**                | Text Search, Nearby Search, Details, Autocomplete |
| **Static Visual**         | Static Maps, Street View                          |
| **Roads**                 | Nearest Roads, Speed Limits                       |
| **Location Services**     | Geolocation API                                   |
| **Embed**                 | Basic, Advanced                                   |
| **Experimental / Others** | Playable Locations API                            |

---

## 7. Notes for Security Testing

* This tool **does not bypass Google limits**.
* Only performs legitimate API calls.
* Use only on keys you **own or are authorized to test**.
* Some APIs may return `UNDETERMINED` when responses are non-standard.

---

and I will generate the file using `python_user_visible`.
```
