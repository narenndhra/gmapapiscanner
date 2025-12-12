# Google Maps API Key Vulnerability Scanner  
A fast, comprehensive, concurrency-enabled scanner that evaluates a Google Maps API key against all major Google Maps Platform endpoints.  
Shows clear **Vulnerable / Secure / Undetermined** statuses with **Rich-powered colored table UI**.

This tool helps security testers, bug bounty researchers, and developers assess the exposure level of a Google Maps API key by directly probing each Maps API endpoint and analyzing the response.

---

## Features

- Full coverage of the most commonly abused Google Maps APIs:
  - Geocoding
  - Directions
  - Places (Text Search, Details, Autocomplete)
  - Static Maps
  - Street View
  - Distance Matrix
  - Roads / Nearest Roads
  - Geolocation
  - Timezone
  - Elevation
  - Embed APIs
  - Playable Locations
  - …and more

- Uses **ThreadPoolExecutor** for concurrency (5× faster scanning).

- Generates a **colored Rich table** summarizing:
  - API name  
  - Status (VULNERABLE / SECURE / UNDETERMINED)  
  - HTTP response code  
  - Reason (parsed message or fallback error)

- Graceful error handling:
  - JSON decode errors
  - HTML responses
  - Network failure
  - Unknown output formats

- Single-file design (`gmaps_scanner.py`) easy to vendor into any project.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/<your-username>/gmaps-api-scanner.git
cd gmaps-api-scanner
