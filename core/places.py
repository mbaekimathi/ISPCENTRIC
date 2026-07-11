"""Location suggestions via Google Places Autocomplete, with Photon/Nominatim fallback.

Live typing uses autocomplete predictions (coords resolved on select when needed).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal, InvalidOperation

from django.conf import settings

# Cache Google availability so we do not wait on a broken key every keystroke.
_google_usable: bool | None = None

_GOOGLE_OK = frozenset({"OK", "ZERO_RESULTS"})
_GOOGLE_DEAD = frozenset(
    {
        "REQUEST_DENIED",
        "INVALID_REQUEST",
        "OVER_QUERY_LIMIT",
        "UNKNOWN_ERROR",
    }
)


def _http_get_json(url: str, timeout: float = 3.0) -> dict | list:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "ISPCENTRIC-LocationSearch/1.0 (ispcentric; contact=support@ispcentric.local)",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _to_decimal(value) -> Decimal | None:
    if value is None or value == "":
        return None
    try:
        dec = Decimal(str(value))
    except (InvalidOperation, TypeError, ValueError):
        return None
    # Match MikroTikRouter.location_lat/lng (max 6 decimal places).
    return dec.quantize(Decimal("0.000001"))


def _suggestion(label: str, lat, lng, *, place_id: str = "", source: str) -> dict | None:
    label = (label or "").strip()
    if not label:
        return None
    return {
        "label": label,
        "place_id": place_id or "",
        "lat": None if lat is None else str(lat),
        "lng": None if lng is None else str(lng),
        "source": source,
    }


def _mark_google(usable: bool) -> None:
    global _google_usable
    _google_usable = usable


def _google_key() -> str:
    return (settings.GOOGLE_MAPS_API_KEY or "").strip()


def _google_enabled() -> bool:
    if not _google_key():
        return False
    if _google_usable is False:
        return False
    return True


def _note_google_status(status: str) -> bool:
    """Return True if status is OK / ZERO_RESULTS. Cache permanent failures."""
    status = (status or "").upper()
    if status in _GOOGLE_OK:
        _mark_google(True)
        return True
    if status in _GOOGLE_DEAD:
        _mark_google(False)
    return False


def google_place_autocomplete(query: str, limit: int = 6) -> list[dict]:
    if not _google_enabled() or not query:
        return []

    params = urllib.parse.urlencode(
        {
            "input": query,
            "types": "geocode",
            "key": _google_key(),
        }
    )
    url = f"https://maps.googleapis.com/maps/api/place/autocomplete/json?{params}"
    try:
        data = _http_get_json(url, timeout=2.5)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, dict):
        return []
    if not _note_google_status(data.get("status") or ""):
        return []

    suggestions = []
    for row in (data.get("predictions") or [])[:limit]:
        label = (row.get("description") or "").strip()
        place_id = (row.get("place_id") or "").strip()
        item = _suggestion(label, None, None, place_id=place_id, source="google")
        if item:
            suggestions.append(item)
    return suggestions


def google_place_details(place_id: str) -> dict | None:
    if not _google_enabled() or not place_id:
        return None

    params = urllib.parse.urlencode(
        {
            "place_id": place_id,
            "fields": "formatted_address,geometry",
            "key": _google_key(),
        }
    )
    url = f"https://maps.googleapis.com/maps/api/place/details/json?{params}"
    try:
        data = _http_get_json(url, timeout=3.0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None

    if not isinstance(data, dict):
        return None
    if (data.get("status") or "").upper() != "OK":
        _note_google_status(data.get("status") or "")
        return None

    _mark_google(True)
    result = data.get("result") or {}
    geometry = result.get("geometry") or {}
    location = geometry.get("location") or {}
    return _suggestion(
        result.get("formatted_address") or "",
        location.get("lat"),
        location.get("lng"),
        place_id=place_id,
        source="google",
    )


def google_geocode(query: str, limit: int = 6) -> list[dict]:
    """Google Geocoding — returns address matches with lat/lng in one call."""
    if not _google_enabled() or not query:
        return []

    params = urllib.parse.urlencode({"address": query, "key": _google_key()})
    url = f"https://maps.googleapis.com/maps/api/geocode/json?{params}"
    try:
        data = _http_get_json(url, timeout=2.5)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, dict):
        return []
    if not _note_google_status(data.get("status") or ""):
        return []

    suggestions = []
    for row in (data.get("results") or [])[:limit]:
        geometry = row.get("geometry") or {}
        location = geometry.get("location") or {}
        item = _suggestion(
            row.get("formatted_address") or "",
            location.get("lat"),
            location.get("lng"),
            place_id=(row.get("place_id") or "").strip(),
            source="google",
        )
        if item and item["lat"] is not None and item["lng"] is not None:
            suggestions.append(item)
    return suggestions


def _photon_label(props: dict) -> str:
    parts = []
    for key in ("name", "street", "housenumber", "district", "city", "county", "state", "country"):
        value = (props.get(key) or "").strip()
        if value and value not in parts:
            parts.append(value)
    if parts:
        return ", ".join(parts)
    return (props.get("name") or "").strip()


def photon_autocomplete(query: str, limit: int = 6) -> list[dict]:
    """Komoot Photon — free OSM typeahead, better for partial queries than Nominatim."""
    if not query:
        return []
    params = urllib.parse.urlencode({"q": query, "limit": limit, "lang": "en"})
    url = f"https://photon.komoot.io/api/?{params}"
    try:
        data = _http_get_json(url, timeout=3.0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []

    features = data.get("features") if isinstance(data, dict) else None
    if not isinstance(features, list):
        return []

    suggestions = []
    seen = set()
    for feature in features[:limit]:
        props = feature.get("properties") or {}
        geometry = feature.get("geometry") or {}
        coords = geometry.get("coordinates") or []
        if len(coords) < 2:
            continue
        lng, lat = coords[0], coords[1]
        label = _photon_label(props)
        key = label.lower()
        if not label or key in seen:
            continue
        seen.add(key)
        osm_type = (props.get("osm_type") or "").strip()
        osm_id = props.get("osm_id")
        place_id = f"{osm_type}:{osm_id}" if osm_type and osm_id is not None else ""
        item = _suggestion(label, lat, lng, place_id=place_id, source="photon")
        if item:
            suggestions.append(item)
    return suggestions


def nominatim_autocomplete(query: str, limit: int = 6) -> list[dict]:
    if not query:
        return []
    params = urllib.parse.urlencode(
        {
            "q": query,
            "format": "jsonv2",
            "addressdetails": 0,
            "limit": limit,
            "dedupe": 1,
        }
    )
    url = f"https://nominatim.openstreetmap.org/search?{params}"
    try:
        data = _http_get_json(url, timeout=4.0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return []

    if not isinstance(data, list):
        return []

    suggestions = []
    seen = set()
    for row in data[:limit]:
        label = (row.get("display_name") or "").strip()
        key = label.lower()
        if key in seen:
            continue
        seen.add(key)
        item = _suggestion(
            label,
            row.get("lat"),
            row.get("lon"),
            place_id=str(row.get("place_id") or row.get("osm_id") or ""),
            source="nominatim",
        )
        if item and item["lat"] is not None and item["lng"] is not None:
            suggestions.append(item)
    return suggestions


def search_locations(query: str, limit: int = 6) -> dict:
    """Live map suggestions as the user types.

    Prefer Google Place Autocomplete (fast partial matches; coords on select).
    Fall back to Photon, then Nominatim, when Google is missing or denied.
    """
    from django.core.cache import cache

    query = (query or "").strip()
    if len(query) < 2:
        return {"ok": True, "source": "", "suggestions": []}

    cache_key = f"places:search:{query.lower()}:{limit}"
    cached = cache.get(cache_key)
    if cached is not None:
        return cached

    # Autocomplete is the right API for typing; do not enrich each row here.
    google = google_place_autocomplete(query, limit=limit)
    if google:
        result = {"ok": True, "source": "google", "suggestions": google}
        cache.set(cache_key, result, 45)
        return result

    # If Places Autocomplete is empty but Geocoding still works (rare), use it.
    if _google_enabled():
        geocoded = google_geocode(query, limit=limit)
        if geocoded:
            result = {"ok": True, "source": "google", "suggestions": geocoded}
            cache.set(cache_key, result, 45)
            return result

    photon = photon_autocomplete(query, limit=limit)
    if photon:
        result = {
            "ok": True,
            "source": "photon",
            "suggestions": photon,
            "google_unavailable": not _google_enabled(),
        }
        cache.set(cache_key, result, 45)
        return result

    nominatim = nominatim_autocomplete(query, limit=limit)
    result = {
        "ok": True,
        "source": "nominatim" if nominatim else "",
        "suggestions": nominatim,
        "google_unavailable": not _google_enabled(),
    }
    cache.set(cache_key, result, 45)
    return result


def resolve_location(query: str = "", *, place_id: str = "") -> dict | None:
    """Resolve a place to a label + latitude/longitude."""
    place_id = (place_id or "").strip()
    query = (query or "").strip()

    if place_id and _google_enabled():
        details = google_place_details(place_id)
        if details and details.get("lat") is not None and details.get("lng") is not None:
            return details

    if not query:
        return None

    google = google_geocode(query, limit=1)
    if google:
        return google[0]

    photon = photon_autocomplete(query, limit=1)
    if photon:
        return photon[0]

    nominatim = nominatim_autocomplete(query, limit=1)
    if nominatim:
        return nominatim[0]
    return None


def apply_resolved_coords(location: str, lat, lng, *, place_id: str = "") -> tuple[str, Decimal | None, Decimal | None]:
    """Ensure location text has numeric coordinates, resolving via maps if needed."""
    location = (location or "").strip()
    lat_dec = _to_decimal(lat)
    lng_dec = _to_decimal(lng)
    if location and lat_dec is not None and lng_dec is not None:
        return location, lat_dec, lng_dec

    resolved = resolve_location(location, place_id=place_id)
    if not resolved:
        return location, lat_dec, lng_dec

    return (
        resolved.get("label") or location,
        _to_decimal(resolved.get("lat")),
        _to_decimal(resolved.get("lng")),
    )
