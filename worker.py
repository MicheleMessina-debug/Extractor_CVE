import os, asyncio, aiohttp, asyncpg, json, time
from dateutil import parser

DATABASE_URL = os.getenv("DATABASE_URL")
NVD_FEED_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", 3600))  

async def wait_for_db():
    """Aspetta che PostgreSQL sia pronto prima di continuare."""
    while True:
        try:
            conn = await asyncpg.connect(DATABASE_URL)
            await conn.close()
            print("✅ Database pronto!")
            break
        except Exception:
            print("DB non pronto, riprovo tra 2 secondi...")
            await asyncio.sleep(2)

async def fetch_nvd_recent(session):
    """Scarica le CVE dall'API NVD v2 (JSON già pronto)."""
    async with session.get(NVD_FEED_URL, timeout=60) as resp:
        if resp.status != 200:
            raise RuntimeError(f"NVD fetch failed {resp.status}")
        return await resp.json()  

async def normalize_and_store(conn, entry):
    """Inserisce o aggiorna una CVE nel database."""
    cve_data = entry.get("cve", {})
    cve_id = cve_data.get("id")

    published_str = cve_data.get("published")
    modified_str = cve_data.get("lastModified")
    published = parser.isoparse(published_str) if published_str else None
    modified = parser.isoparse(modified_str) if modified_str else None

    summary = ""
    for d in cve_data.get("descriptions", []):
        if d.get("lang") == "en":
            summary = d.get("value", "")
            break

    cvss = None
    try:
        metrics = cve_data.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    except Exception:
        cvss = None

    raw = json.dumps(entry)

    # Inserimento nel DB
    row = await conn.fetchrow("""
        INSERT INTO vulns (cve_id, source, published_at, last_modified, summary, cvss_score, raw_json)
        VALUES ($1,'nvd',$2,$3,$4,$5,$6)
        ON CONFLICT (source, cve_id)
        DO UPDATE SET last_modified=$3, summary=$4, cvss_score=$5, raw_json=$6
        RETURNING id
    """, cve_id, published, modified, summary, cvss, raw)
    vuln_id = row["id"]

    try:
        configs = entry.get("configurations", [])
        cpes = []
        for node_group in configs:
            for node in node_group.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe23 = match.get("criteria")
                    if cpe23:
                        parts = cpe23.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            version = match.get("versionStartIncluding") or match.get("versionEndIncluding") or ""
                            cpes.append((vendor.lower(), product.lower(), version))
        await conn.execute("DELETE FROM vuln_affected WHERE vuln_id=$1", vuln_id)
        for v, p, vr in cpes:
            await conn.execute(
                "INSERT INTO vuln_affected (vuln_id, vendor, product, version_range) VALUES ($1,$2,$3,$4)",
                vuln_id, v, p, vr
            )
    except Exception:
        pass

    return vuln_id

async def run_once(pool):
    """Scarica le CVE e le inserisce nel DB."""
    async with pool.acquire() as conn:
        headers = {"User-Agent": "VulnMonWorker/1.0 (mikimegov@gmail.com)"}
        async with aiohttp.ClientSession(headers=headers) as session:
            data = await fetch_nvd_recent(session)
            cves = data.get("vulnerabilities", []) 
            print(f"🔹 Trovate {len(cves)} CVE da inserire")
            for entry in cves:
                try:
                    vuln_id = await normalize_and_store(conn, entry)
                    print(f"✔ Inserita CVE {entry['cve']['id']} (id={vuln_id})")
                except Exception as e:
                    print(f"⚠ Errore inserimento {entry.get('cve', {}).get('id')}:", e)

async def main_loop():
    await wait_for_db()
    pool = await asyncpg.create_pool(dsn=DATABASE_URL, min_size=1, max_size=5)
    while True:
        try:
            await run_once(pool)
        except Exception as e:
            print("⚠ Worker error:", e)
        print(f"⏱ Sleeping {POLL_INTERVAL} seconds...")
        await asyncio.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    asyncio.run(main_loop())
