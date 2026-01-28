from flask import jsonify
import json
from pathlib import Path


def _json_from_file(pathstr: str):
    try:
        path = Path(pathstr)
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return jsonify({
            "error": "demo_json_not_found",
            "detail": f"File not found: {str(pathstr)}"
        }), 500

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as e:
        return jsonify({
            "error": "demo_json_invalid",
            "detail": f"Invalid JSON in {str(path)}: {e}"
        }), 500

    return jsonify(payload), 200
