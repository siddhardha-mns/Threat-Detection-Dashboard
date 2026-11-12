"""
geo.py - Member B (NLP & Risk)
Maps src_ip to country, lat, and lon using MaxMind GeoLite2 or deterministic fallback.
"""
import hashlib
from typing import Dict, Any

COUNTRY_COORDINATES = {
    'United States': (37.7749, -122.4194, 0.25),
    'China': (39.9042, 116.4074, 0.85),
    'Russia': (55.7558, 37.6173, 0.90),
    'Germany': (52.5200, 13.4050, 0.30),
    'United Kingdom': (51.5074, -0.1278, 0.25),
    'Brazil': (-23.5505, -46.6333, 0.50),
    'Netherlands': (52.3676, 4.9041, 0.35),
    'India': (28.6139, 77.2090, 0.45),
    'France': (48.8566, 2.3522, 0.25),
    'Japan': (35.6762, 139.6503, 0.20),
    'North Korea': (39.0392, 125.7625, 0.95),
    'Iran': (35.6892, 51.3890, 0.88),
}

COUNTRIES = list(COUNTRY_COORDINATES.keys())

def lookup_ip(ip: str) -> Dict[str, Any]:
    """
    Returns country, lat, lon, and risk_factor for a given IP address.
    Uses GeoLite2 if geoip2 is installed, otherwise deterministic hash fallback.
    """
    try:
        import geoip2.database
        with geoip2.database.Reader('data/GeoLite2-City.mmdb') as reader:
            response = reader.city(ip)
            cname = response.country.name or 'Unknown'
            risk = 0.5
            if cname in COUNTRY_COORDINATES:
                risk = COUNTRY_COORDINATES[cname][2]
            return {
                'country': cname,
                'lat': response.location.latitude or 0.0,
                'lon': response.location.longitude or 0.0,
                'risk_factor': risk
            }
    except Exception:
        # Deterministic hash fallback
        h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
        country = COUNTRIES[h % len(COUNTRIES)]
        base_lat, base_lon, risk = COUNTRY_COORDINATES[country]
        jitter_lat = base_lat + ((h % 100) - 50) / 40.0
        jitter_lon = base_lon + (((h // 100) % 100) - 50) / 40.0
        return {
            'country': country,
            'lat': round(jitter_lat, 4),
            'lon': round(jitter_lon, 4),
            'risk_factor': risk
        }
