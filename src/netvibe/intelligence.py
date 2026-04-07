"""
intelligence.py - Threat Intelligence enrichment for NetVibe.

Handles IP reputation lookups using AbuseIPDB (or simulation mode).
Includes a local caching layer to respect API rate limits.
"""

import os
import httpx
import logging
import asyncio
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# --- Configuration ---
# Set ABUSEIPDB_API_KEY in environment to enable real lookups
API_KEY = os.getenv("ABUSEIPDB_API_KEY")
CACHE_TTL_DAYS = 2

class IntelEngine:
    def __init__(self, db_conn):
        self.db = db_conn
        self.client = httpx.AsyncClient(timeout=10.0)

    async def get_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """
        Main entry point for IP enrichment.
        Checks local cache first, then calls external API or simulation.
        """
        # 1. Check local cache
        from netvibe.database import get_reputation
        cached = get_reputation(self.db, ip)
        
        if cached:
            last_checked = datetime.fromisoformat(cached['last_checked'])
            if datetime.utcnow() - last_checked < timedelta(days=CACHE_TTL_DAYS):
                logger.debug(f"Cache hit for {ip}")
                return cached

        # 2. Fetch fresh data
        if API_KEY and API_KEY != "YOUR_API_KEY_HERE":
            data = await self._fetch_abuseipdb(ip)
        else:
            data = await self._simulate_reputation(ip)

        # 3. Update cache
        from netvibe.database import update_reputation
        update_reputation(self.db, data)
        return data

    async def _fetch_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Call real AbuseIPDB API."""
        url = "https://api.abuseipdb.com/api/v2/check"
        params = {
            "ipAddress": ip,
            "maxAgeInDays": "90"
        }
        headers = {
            "Accept": "application/json",
            "Key": API_KEY
        }
        
        try:
            response = await self.client.get(url, headers=headers, params=params)
            if response.status_code == 200:
                res_data = response.json().get("data", {})
                score = res_data.get("abuseConfidenceScore", 0)
                return {
                    "ip": ip,
                    "score": score,
                    "is_malicious": score > 50,
                    "provider": "AbuseIPDB",
                    "tags": ", ".join(res_data.get("usageType", "").split()) or "Unknown",
                    "raw_data": response.text
                }
            else:
                logger.warning(f"AbuseIPDB API error ({response.status_code}): {response.text}")
                return await self._simulate_reputation(ip) # Fallback
        except Exception as e:
            logger.error(f"Failed to connect to AbuseIPDB: {e}")
            return await self._simulate_reputation(ip)

    async def _simulate_reputation(self, ip: str) -> Dict[str, Any]:
        """Deterministic simulation of reputation based on IP hash."""
        # Use MD5 hash of IP to generate a consistent "fake" score
        hasher = hashlib.md5(ip.encode()).hexdigest()
        seed = int(hasher[:4], 16)
        
        # Logic: 
        # Most IPs are clean (score < 10)
        # 10% are suspicious (score 40-70)
        # 2% are malicious (score 80-100)
        if seed % 100 < 2:
            score = 85 + (seed % 15)
            tags = "Botnet, SQL Injection"
        elif seed % 100 < 12:
            score = 45 + (seed % 30)
            tags = "Scanner, Data Center"
        else:
            score = seed % 15
            tags = "Retail, Clean"

        return {
            "ip": ip,
            "score": score,
            "is_malicious": score > 75,
            "provider": "Simulation",
            "tags": tags,
            "raw_data": '{"info": "Simulated data for development"}'
        }

    async def close(self):
        await self.client.aclose()
