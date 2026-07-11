"""Compress and resize profile photos so pages load faster."""

from io import BytesIO

from django.core.files.uploadedfile import InMemoryUploadedFile
from PIL import Image, ImageOps

# Avatars display at ~32–76px; 512px covers retina without huge downloads.
MAX_SIDE = 512
JPEG_QUALITY = 82


def optimize_profile_photo(uploaded_file):
    """Return a smaller JPEG when the upload is a large image; otherwise pass through."""
    if not uploaded_file:
        return uploaded_file

    try:
        uploaded_file.seek(0)
        image = Image.open(uploaded_file)
        image = ImageOps.exif_transpose(image)
        image.load()
    except Exception:
        if hasattr(uploaded_file, "seek"):
            uploaded_file.seek(0)
        return uploaded_file

    if image.mode not in ("RGB", "L"):
        image = image.convert("RGB")
    elif image.mode == "L":
        image = image.convert("RGB")

    width, height = image.size
    if max(width, height) > MAX_SIDE:
        image.thumbnail((MAX_SIDE, MAX_SIDE), Image.Resampling.LANCZOS)

    buffer = BytesIO()
    image.save(buffer, format="JPEG", quality=JPEG_QUALITY, optimize=True)
    buffer.seek(0)

    name = getattr(uploaded_file, "name", "photo.jpg") or "photo.jpg"
    base = name.rsplit(".", 1)[0]
    filename = f"{base}.jpg"

    return InMemoryUploadedFile(
        file=buffer,
        field_name=getattr(uploaded_file, "field_name", None),
        name=filename,
        content_type="image/jpeg",
        size=buffer.getbuffer().nbytes,
        charset=None,
    )


def maybe_optimize_image_field(field_file):
    """Optimize only newly assigned uploads (not already-stored files)."""
    if not field_file:
        return field_file
    if getattr(field_file, "_committed", True):
        return field_file
    return optimize_profile_photo(field_file)
