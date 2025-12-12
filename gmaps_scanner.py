#!/usr/bin/env python3
# gmaps_scanner.py
# Single-file Google Maps API key scanner (Python 3.11)
# - Concurrency enabled (ThreadPoolExecutor)
# - No screenshot support (user chose "ignore")
# - Exports to JSON/CSV optional
# - Robust and defensive against non-JSON responses

from __future__ import annotations
import argparse
import csv
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

# optional imports will be checked at runtime
try:
    import requests
except Exception:  # pragma: no cover - fail gracefully
    requests = None

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
except Exception:  # pragma: no cover - fail gracefully
    Console = None

# ----------------------------- Configuration ---------------------------------
# Expanded list of endpoints to test. Each entry: (friendly_name, method, url_template)
API_TESTS = [
    ("Staticmap API", "GET", "https://maps.googleapis.com/maps/api/staticmap?center=40.714224,-73.961452&zoom=12&size=400x400&key={key}"),
    ("Streetview API", "GET", "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&key={key}"),
    ("Geocode API", "GET", "https://maps.googleapis.com/maps/api/geocode/json?address=New+York&key={key}"),
    ("Reverse Geocode API", "GET", "https://maps.googleapis.com/maps/api/geocode/json?latlng=40.714224,-73.961452&key={key}"),
    ("Elevation API", "GET", "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={key}"),
    ("Timezone API", "GET", "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={key}"),
    ("Directions API", "GET", "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key={key}"),
    ("Distance Matrix API", "GET", "https://maps.googleapis.com/maps/api/distancematrix/json?origins=Seattle&destinations=San+Francisco&key={key}"),
    ("Nearest Roads API", "GET", "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795&key={key}"),
    ("Snap To Roads API", "GET", "https://roads.googleapis.com/v1/snapToRoads?path=60.170880,24.942795&key={key}"),
    ("Speed Limits API", "GET", "https://roads.googleapis.com/v1/speedLimits?placeId=ChIJVTPokywQkFQRmtVEaUZlJRA&key={key}"),
    ("Places Text Search API", "GET", "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Seattle&key={key}"),
    ("Places Nearby Search API", "GET", "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=47.6062,-122.3321&radius=1500&type=restaurant&key={key}"),
    ("Places Find Place API", "GET", "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=restaurants%20in%20Seattle&inputtype=textquery&key={key}"),
    ("Place Details API", "GET", "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&key={key}"),
    ("Place Autocomplete API", "GET", "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Starbucks&key={key}"),
    ("Places Photo (image)", "GET", "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=ATtYBwL...&key={key}"),
    ("Playable Locations API", "POST", "https://playablelocations.googleapis.com/v3:samplePlayableLocations?key={key}"),
    ("Geolocation API", "POST", "https://www.googleapis.com/geolocation/v1/geolocate?key={key}"),
    ("Maps Embed (basic)", "GET", "https://www.google.com/maps/embed/v1/place?key={key}&q=Space+Needle,Seattle+WA"),
]

# POST payloads for some endpoints
POST_PAYLOADS: Dict[str, Dict[str, Any]] = {
    "https://playablelocations.googleapis.com/v3:samplePlayableLocations?key={key}": {
        "area_filter": {"s2_cell_id": 7715420662885515264},
        "criteria": [{"gameObjectType": 1, "filter": {"maxLocationCount": 1}, "fields_to_return": {"paths": ["name"]}}],
    },
    "https://www.googleapis.com/geolocation/v1/geolocate?key={key}": {"considerIp": True},
}

# Default user agent and request headers
DEFAULT_HEADERS = {"User-Agent": "gmaps_scanner/1.0 (+https://example.local)"}

# ----------------------------- Utility functions -----------------------------
def safe_json(resp: "requests.Response") -> Optional[Dict[str, Any]]:
    """Return JSON body or None if not parseable."""
    try:
        return resp.json()
    except Exception:
        return None

def summarize_text_snippet(text: str, length: int = 300) -> str:
    text = text.strip().replace("\n", " ")
    if len(text) <= length:
        return text
    return text[:length].rstrip() + "..."

def analyze_response(api_name: str, status: int, headers: Dict[str, Any], text: str, j: Optional[Dict[str, Any]]) -> Tuple[str, str]:
    """
    Decide vulnerability label and reason.
    Labels: VULNERABLE, SECURE, UNDETERMINED
    """
    content_type = (headers.get("Content-Type") or "").lower()
    # 200 OK cases
    if status == 200:
        if j:
            # heuristic: presence of expected result-like keys
            if any(k in j for k in ("results", "routes", "candidates", "snappedPoints", "locations", "place_id", "rows", "predictions")):
                return "VULNERABLE", "200 OK with data-looking JSON"
            # geolocation returns location
            if isinstance(j, dict) and ("location" in j or "location" in j.get("results", [{}])[0] if j.get("results") else False):
                return "VULNERABLE", "200 OK with location data"
            # JSON but error structure
            if "error" in j:
                # often error inside 200: treat as SECURE
                try:
                    msg = j["error"].get("message", str(j["error"]))
                except Exception:
                    msg = str(j["error"])
                return "SECURE", f"200 OK but error present: {msg}"
            # unknown JSON body
            return "UNDETERMINED", "200 OK with JSON body that lacks known data fields"
        else:
            # Non-JSON 200: could be image or HTML
            if "image" in content_type or api_name.lower().startswith("staticmap") or "photo" in api_name.lower():
                return "UNDETERMINED", f"200 OK with image Content-Type: {content_type or 'unknown'}"
            if text.strip().lower().startswith("<!doctype") or text.strip().lower().startswith("<html"):
                return "SECURE", f"200 OK but returned HTML page (possibly gateway/redirect)"
            return "UNDETERMINED", "200 OK with non-JSON body"
    # Non-200 cases: inspect JSON error if present
    if j:
        # Google error structure may be { "error": { "code": 403, "message": "..." } }
        err = j.get("error")
        if isinstance(err, dict):
            msg = err.get("message") or json.dumps(err)
            return "SECURE", f"{status} {msg}"
        # other error fields
        msg = j.get("error_message") or j.get("message") or str(j)
        return "SECURE", f"{status} {msg}"
    # Non-JSON non-200: return HTTP status and snippet
    snippet = summarize_text_snippet(text, 300)
    return "SECURE", f"{status} {snippet or 'No response body'}"

# ----------------------------- Network worker --------------------------------
def test_one(api_name: str, method: str, url_template: str, key: str, timeout: int = 8) -> Dict[str, Any]:
    """Perform a single API test and return a structured result."""
    url = url_template.format(key=key)
    body = POST_PAYLOADS.get(url_template)
    result = {
        "api": api_name,
        "method": method,
        "url": url,
        "http_status": None,
        "label": "UNDETERMINED",
        "reason": "Not tested",
        "response_snippet": None,
    }

    if requests is None:
        result.update({"label": "UNDETERMINED", "reason": "requests library not installed"})
        return result

    headers = DEFAULT_HEADERS.copy()
    try:
        if method.upper() == "GET":
            resp = requests.get(url, headers=headers, timeout=timeout)
        else:
            resp = requests.post(url, json=body, headers=headers, timeout=timeout)
    except requests.RequestException as e:
        result.update({"label": "UNDETERMINED", "reason": f"Request failed: {e}"})
        return result

    resp_text = resp.text or ""
    resp_json = safe_json(resp)
    label, reason = analyze_response(api_name, resp.status_code, resp.headers, resp_text, resp_json)
    snippet = None
    # include JSON summary or small body snippet for debug
    if resp_json:
        try:
            snippet = json.dumps(resp_json if isinstance(resp_json, dict) else {"value": resp_json})[:500]
        except Exception:
            snippet = summarize_text_snippet(str(resp_json), 300)
    else:
        snippet = summarize_text_snippet(resp_text, 500)

    result.update({
        "http_status": resp.status_code,
        "label": label,
        "reason": reason,
        "response_snippet": snippet,
    })
    return result

# ----------------------------- Scanning coordinator ---------------------------
def scan_all(key: str, concurrency: int = 10, timeout: int = 8, delay: float = 0.0, apis = None) -> List[Dict[str, Any]]:
    """Run tests for all APIs concurrently and return the list of results in the same order as API_TESTS."""
    apis = apis if apis is not None else API_TESTS
    results_by_index: Dict[int, Dict[str, Any]] = {}
    tasks = []
    with ThreadPoolExecutor(max_workers=max(2, concurrency)) as exe:
        futures = {}
        for idx, (api_name, method, url_template) in enumerate(apis):
            futures[exe.submit(test_one, api_name, method, url_template, key, timeout)] = idx
            if delay and delay > 0:
                time.sleep(delay)
        # collect
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                res = fut.result()
            except Exception as e:
                res = {
                    "api": apis[idx][0],
                    "method": apis[idx][1],
                    "url": apis[idx][2].format(key=key),
                    "http_status": None,
                    "label": "UNDETERMINED",
                    "reason": f"Exception in worker: {e}",
                    "response_snippet": None,
                }
            results_by_index[idx] = res
    # Reorder to original order
    return [results_by_index[i] for i in range(len(apis))]

# ----------------------------- Output helpers --------------------------------
def print_results_table(results: List[Dict[str, Any]]):
    """Print the results using rich.Table; falls back to plain text if rich is unavailable."""
    if Console is None:
        # plain text fallback
        for r in results:
            print(f"{r['api']:<30} | {r['label']:<12} | {r['http_status']!s:<4} | {r['reason']}")
        return

    console = Console()
    table = Table(title="Google Maps API Vulnerability Report", box=box.MINIMAL_DOUBLE_HEAD, show_lines=False)
    table.add_column("API", style="bold cyan", no_wrap=True)
    table.add_column("Status", style="bold")
    table.add_column("HTTP", justify="right")
    table.add_column("Reason / Notes", style="dim")

    vulnerables = 0
    for r in results:
        lbl = r.get("label", "UNDETERMINED")
        if lbl == "VULNERABLE":
            status = "[bold red]VULNERABLE[/bold red]"
            vulnerables += 1
        elif lbl == "SECURE":
            status = "[green]SECURE[/green]"
        else:
            status = "[yellow]UNDETERMINED[/yellow]"
        table.add_row(r["api"], status, str(r.get("http_status", "")), r.get("reason", ""))
    console.print(table)
    console.print(Panel(f"Vulnerable APIs found: [bold red]{vulnerables}[/bold red]", title="Summary"))

def save_json(results: List[Dict[str, Any]], path: str):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(results, fh, ensure_ascii=False, indent=2)

def save_csv(results: List[Dict[str, Any]], path: str):
    keys = ["api", "method", "url", "http_status", "label", "reason", "response_snippet"]
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        for r in results:
            w.writerow({k: r.get(k, "") for k in keys})

# ----------------------------- CLI / Main ------------------------------------
def parse_args():
    p = argparse.ArgumentParser(prog="gmaps_scanner.py", description="Google Maps API key scanner (single-file). Only run against keys you own or have permission to test.")
    p.add_argument("--key", "-k", help="Google Maps API key to test")
    p.add_argument("--demo", action="store_true", help="Run demo mode (no network calls)")
    p.add_argument("--concurrency", "-c", type=int, default=10, help="Number of concurrent workers (default: 10)")
    p.add_argument("--timeout", type=int, default=8, help="HTTP timeout seconds (default: 8)")
    p.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between scheduling requests (throttling)")
    p.add_argument("--output-json", type=str, help="Save results to JSON file")
    p.add_argument("--output-csv", type=str, help="Save results to CSV file")
    p.add_argument("--no-color", action="store_true", help="Disable rich colors (if Console installed will still be used)")
    return p.parse_args()

def demo_results() -> List[Dict[str, Any]]:
    sample = [
        {"api": "Staticmap API", "method": "GET", "url": "", "http_status": 403, "label": "SECURE", "reason": "403 The Google Maps Platform server rejected your request. This API project is not authorized to use this API.", "response_snippet": ""},
        {"api": "Geocode API", "method": "GET", "url": "", "http_status": 200, "label": "VULNERABLE", "reason": "200 OK with data-looking JSON", "response_snippet": '{"results":[...}]'},
        {"api": "Directions API", "method": "GET", "url": "", "http_status": 200, "label": "VULNERABLE", "reason": "200 OK with data-looking JSON", "response_snippet": '{"routes":[...}]'},
        {"api": "Place Details API", "method": "GET", "url": "", "http_status": 200, "label": "UNDETERMINED", "reason": "200 OK with JSON body that lacks known data fields", "response_snippet": '{"unknown": "value"}'},
        {"api": "Playable Locations API", "method": "POST", "url": "", "http_status": 404, "label": "SECURE", "reason": "404 <!DOCTYPE html> ...", "response_snippet": "<!doctype html>"},
    ]
    return sample

def main():
    args = parse_args()

    # handle missing deps
    if requests is None:
        print("This script requires the 'requests' package. Install with: pip install requests")
        sys.exit(2)
    if Console is None and not args.no_color:
        # continue but warn; script will still run in plain text
        print("Note: 'rich' package not installed. Output will be plain text. Install with: pip install rich")

    if args.demo:
        results = demo_results()
        print_results_table(results)
        if args.output_json:
            save_json(results, args.output_json)
            print(f"Saved demo JSON to {args.output_json}")
        if args.output_csv:
            save_csv(results, args.output_csv)
            print(f"Saved demo CSV to {args.output_csv}")
        return

    if not args.key:
        print("Missing required --key argument. Use --key YOUR_API_KEY or run with --demo.")
        sys.exit(1)

    # perform scan
    start = time.time()
    results = scan_all(key=args.key, concurrency=args.concurrency, timeout=args.timeout, delay=args.delay)
    elapsed = time.time() - start

    # output
    print_results_table(results)
    print(f"Scan completed in {elapsed:.2f} seconds.")

    # exports
    if args.output_json:
        save_json(results, args.output_json)
        print(f"Saved JSON output to {args.output_json}")
    if args.output_csv:
        save_csv(results, args.output_csv)
        print(f"Saved CSV output to {args.output_csv}")

if __name__ == "__main__":
    main()

