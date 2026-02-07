# Street View Integration Example - Flask Backend
# Serves Street View data and manages API calls to minimize cost

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
from typing import Dict, Optional
import requests
import time
from functools import lru_cache

app = Flask(__name__)
CORS(app)

GOOGLE_MAPS_API_KEY = os.getenv('GOOGLE_MAPS_API_KEY')
MAPILLARY_ACCESS_TOKEN = os.getenv('MAPILLARY_ACCESS_TOKEN')

# Cache to reduce API calls
class StreetViewCache:
    def __init__(self, ttl_seconds=3600):
        self.cache = {}
        self.ttl = ttl_seconds

    def get(self, key):
        if key in self.cache:
            entry = self.cache[key]
            if time.time() - entry['time'] < self.ttl:
                return entry['data']
            else:
                del self.cache[key]
        return None

    def set(self, key, data):
        self.cache[key] = {'data': data, 'time': time.time()}

sv_cache = StreetViewCache(ttl_seconds=7200)

@app.route('/api/streetview/metadata', methods=['POST'])
def get_streetview_metadata():
    """
    Get Street View metadata for coordinates
    Caches to avoid repeated API calls
    """
    data = request.json
    lat = data['lat']
    lng = data['lng']

    cache_key = f"sv:{lat},{lng}"
    cached = sv_cache.get(cache_key)

    if cached:
        return jsonify({'success': True, 'data': cached, 'cached': True})

    # Call Google Street View API
    params = {
        'location': f'{lat},{lng}',
        'key': GOOGLE_MAPS_API_KEY,
        'source': 'outdoor'
    }

    try:
        response = requests.get(
            'https://maps.googleapis.com/maps/api/streetview/metadata',
            params=params,
            timeout=5
        )
        metadata = response.json()

        if metadata.get('status') == 'OK':
            sv_cache.set(cache_key, metadata)
            return jsonify({'success': True, 'data': metadata, 'cached': False})
        else:
            return jsonify({
                'success': False,
                'error': metadata.get('status', 'Unknown error'),
                'message': 'No Street View data available for this location'
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/api/streetview/coverage', methods=['GET'])
def check_streetview_coverage():
    """Check if Street View is available at coordinates"""
    lat = request.args.get('lat', type=float)
    lng = request.args.get('lng', type=float)

    if not lat or not lng:
        return jsonify({'error': 'Missing coordinates'}), 400

    params = {
        'location': f'{lat},{lng}',
        'key': GOOGLE_MAPS_API_KEY
    }

    response = requests.get(
        'https://maps.googleapis.com/maps/api/streetview/metadata',
        params=params
    )

    metadata = response.json()
    available = metadata.get('status') == 'OK'

    return jsonify({
        'available': available,
        'status': metadata.get('status'),
        'pano_id': metadata.get('pano_id') if available else None
    })

@app.route('/api/mapillary/search', methods=['POST'])
def search_mapillary_images():
    """Search Mapillary images near coordinates"""
    data = request.json
    lat = data['lat']
    lng = data['lng']

    query = f"""
    {{
        imageSearch(
            bbox: [{lng-0.001}, {lat-0.001}, {lng+0.001}, {lat+0.001}]
            first: 5
        ) {{
            edges {{
                node {{
                    id
                    geometry {{ coordinates }}
                    capturedAt
                    sequence {{ id }}
                }}
            }}
        }}
    }}
    """

    headers = {'Authorization': f'OAuth {MAPILLARY_ACCESS_TOKEN}'}

    response = requests.post(
        'https://graph.mapillary.com/graphql',
        json={'query': query},
        headers=headers
    )

    if response.status_code == 200:
        return jsonify(response.json())
    else:
        return jsonify({'error': 'Mapillary query failed'}), 400

@app.route('/api/streetview/nearby', methods=['GET'])
def get_nearby_streetview():
    """Get nearby Street View panoramas"""
    lat = request.args.get('lat', type=float)
    lng = request.args.get('lng', type=float)
    radius_m = request.args.get('radius', 100, type=int)

    # Convert meters to degrees (approximately)
    lat_delta = (radius_m / 111000.0)
    lng_delta = (radius_m / (111000.0 * abs(__import__('math').cos(__import__('math').radians(lat)))))

    params = {
        'location': f'{lat},{lng}',
        'radius': radius_m,
        'key': GOOGLE_MAPS_API_KEY,
        'source': 'outdoor'
    }

    response = requests.get(
        'https://maps.googleapis.com/maps/api/streetview/metadata',
        params=params
    )

    return jsonify(response.json())

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5002)
