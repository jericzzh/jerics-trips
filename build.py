#!/usr/bin/env python3
"""Build the password-locked, view-only Jeric's Trips page.
Usage: python3 build.py <trips_json_dir> <password> [out=index.html]
Reads every trip JSON (ArtifactData out_dir files), strips booking references,
home location and costs, embeds them as a read-only snapshot in app-template.html,
then encrypts the whole page (AES-256-GCM, PBKDF2-SHA256) behind a password screen."""
import sys, os, re, json, glob, time, base64, secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

HERE = os.path.dirname(os.path.abspath(__file__))
ITER = 310000
REF = [r'[Cc]onf(?:irmation)?\.?\s*(?:#|no\.?|number)?\s*:?\s*[A-Z0-9-]{5,}', r'#\s?[A-Z0-9-]*\d[A-Z0-9-]{4,}',
       r'[Tt]ravel file\s+[A-Z0-9]{5,}', r'e-?ticket\s*(?:#|no\.?)?\s*\d{8,}', r'\b[Rr]ef(?:erence)?\.?\s*#?\s*[0-9A-Z-]{6,}',
       r'[Bb]ooking\s*(?:#|no\.?|number|ref)\s*:?\s*[A-Z0-9-]{4,}',
       r'\b\d{8,}\b', r'\b(?:PNR|[Ll]ocator|[Cc]ode|[Rr]eservation)\s*:?\s*[A-Z0-9]{5,8}\b', r'\b\d{4}-\d{2}-[A-Z]{2}\d{3,}\b', r'\b\d{8}-[A-Z]{2}\d{3,}\b']

KNOWN = set()
def clean_text(s):
    s = s or ""
    for k in sorted(KNOWN, key=len, reverse=True): s = s.replace(k, "[ref hidden]")
    for p in REF: s = re.sub(p, "[ref hidden]", s)
    s = re.sub(r'Home \([^)]*\)', 'Home', s)
    return s

def sanitize(t):
    t = {k: v for k, v in t.items() if k not in ("sharedUrl",)}
    items = []
    for i in t.get("items", []):
        i = dict(i)
        i["confirmation"] = ""
        i.pop("cost", None); i.pop("review", None); i.pop("source", None)
        for f in ("notes", "title", "location", "from", "to"):
            if f in i: i[f] = clean_text(i[f])
        if (i.get("from") or "").startswith("Home"): i.pop("fromLat", None); i.pop("fromLng", None)
        if (i.get("to") or "").startswith("Home"): i.pop("toLat", None); i.pop("toLng", None)
        items.append(i)
    t["items"] = items
    t["notes"] = clean_text(t.get("notes"))
    return t

def main():
    src, pw = sys.argv[1], sys.argv[2]
    out = sys.argv[3] if len(sys.argv) > 3 else os.path.join(HERE, "index.html")
    raws = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(src, "*.json")))]
    for d in raws:
        for i in (d.get("data", d).get("items") or []):
            for part in re.split(r'[\s,/;]+', str(i.get("confirmation") or "")):
                part = part.strip("#().")
                if len(part) >= 4: KNOWN.add(part)
    trips = []
    for f in sorted(glob.glob(os.path.join(src, "*.json"))):
        d = json.load(open(f)); d = d.get("data", d)
        d.setdefault("id", os.path.splitext(os.path.basename(f))[0])
        trips.append(sanitize(d))
    snap = {"title": "Jeric's Trips", "updatedAt": int(time.time() * 1000), "trips": trips, "photos": {}}
    app = open(os.path.join(HERE, "app-template.html"), encoding="utf-8").read()
    tag = '<script id="snapshot-data" type="application/json">' + json.dumps(snap, ensure_ascii=False).replace("</", "<\\/") + "</script>"
    app = re.sub(r'<body([^>]*)>', lambda m: m.group(0) + tag, app, count=1)
    app = re.sub(r'<title>.*?</title>', "<title>Jeric's Trips</title>", app, count=1)
    salt, iv = secrets.token_bytes(16), secrets.token_bytes(12)
    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITER).derive(pw.encode())
    ct = AESGCM(key).encrypt(iv, app.encode("utf-8"), None)
    payload = {"s": base64.b64encode(salt).decode(), "i": base64.b64encode(iv).decode(), "n": ITER, "c": base64.b64encode(ct).decode()}
    lock = open(os.path.join(HERE, "lock-template.html"), encoding="utf-8").read()
    open(out, "w", encoding="utf-8").write(lock.replace("__PAYLOAD__", json.dumps(payload)))
    print(f"built {out}: {len(trips)} trips, {len(ct)//1024} KB encrypted")

if __name__ == "__main__": main()
