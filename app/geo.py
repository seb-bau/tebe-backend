from app.models import Geolocation
from wowicache.models import WowiCache, Building
from flask import current_app
from app.extensions import db
import requests
from urllib.parse import urlencode
import logging
import time
import math

logger = logging.getLogger('root')

LAST_REQUEST_TIME = 0
REQUEST_INTERVAL = 0.25  # limit


def haversine_distance_m(lat1, lon1, lat2, lon2):
    R = 6371000  # Erdradius in METERN

    if not lat1 or not lon1 or not lat2 or not lon2:
        return None

    lat1, lon1, lat2, lon2 = map(math.radians, [
        float(lat1), float(lon1), float(lat2), float(lon2)
    ])

    dlat = lat2 - lat1
    dlon = lon2 - lon1

    a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

    return R * c


def get_buildings_in_radius_m(center_lat, center_lon, radius_m):
    center_lat = float(center_lat)
    center_lon = float(center_lon)

    geolocations = Geolocation.query.all()
    result = []

    for geo in geolocations:
        distance_m = haversine_distance_m(
            center_lat, center_lon,
            float(geo.lat), float(geo.lon)
        )

        if distance_m <= radius_m:
            item = {
                "id": geo.id,
                "building_id": geo.building_id,
                "building_idnum": geo.building_idnum,
                "lat": geo.lat,
                "lon": geo.lon,
                "distance_m": round(distance_m, 1)
            }
            result.append(item)

    return result


def geocode_address(address: str, api_key: str) -> tuple[str, str] | tuple[None, None]:
    global LAST_REQUEST_TIME

    now = time.time()
    elapsed = now - LAST_REQUEST_TIME
    if elapsed < REQUEST_INTERVAL:
        time.sleep(REQUEST_INTERVAL - elapsed)

    LAST_REQUEST_TIME = time.time()

    base_url = "https://api.geoapify.com/v1/geocode/search"
    params = {
        "text": address,
        "format": "json",
        "apiKey": api_key,
        "lang": "de",
        "limit": 1,
        "filter": "countrycode:de"
    }

    url = f"{base_url}?{urlencode(params)}"
    response = requests.get(url)
    data = response.json()

    if "results" in data and len(data["results"]) > 0:
        lat = str(data["results"][0]["lat"])
        lon = str(data["results"][0]["lon"])
        return lat, lon

    return None, None


def update_geolocation(force_update: bool = False):
    with current_app.app_context():
        cache = WowiCache(current_app.config['INI_CONFIG'].get("Wowicache", "connection_uri"))
        geo_api_key = current_app.config['INI_CONFIG'].get("Geolocation", "api_key")
        building: Building
        buildings = cache.session.query(Building).all()
        print(len(buildings))
        for building in buildings:
            if building.building_type_name != "Mehrfamilienhaus":
                continue
            if not force_update:
                existing = db.session.query(Geolocation).filter(Geolocation.building_id == building.internal_id).first()
                if existing:
                    continue

            building_address = f"{building.street_complete} {building.postcode}  {building.town}"
            lat, lon = geocode_address(building_address, geo_api_key)
            if not lat:
                print(f"No Geolocation for {building_address}")
                continue
            # print(f"{building_address} --> {lat}, {lon}")

            new_geo = Geolocation(
                building_id=building.internal_id,
                building_idnum=building.id_num,
                lat=lat,
                lon=lon
            )

            db.session.add(new_geo)
            db.session.commit()
