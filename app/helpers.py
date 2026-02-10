from flask import jsonify
import json
from pathlib import Path
from PIL import Image, ImageOps


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


def normalize_exif_orientation(path: str) -> None:

    with Image.open(path) as im:
        im2 = ImageOps.exif_transpose(im)

        fmt = (im.format or "JPEG").upper()

        if fmt not in ("JPEG", "JPG", "PNG"):
            fmt = "JPEG"
            im2 = im2.convert("RGB")

        if fmt in ("JPEG", "JPG"):
            im2 = im2.convert("RGB")
            im2.save(path, format="JPEG", quality=90, optimize=True)
        else:
            im2.save(path, format="PNG", optimize=True)
