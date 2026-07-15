"""MikroTik model catalog for onboard UI (labels + product images)."""

from __future__ import annotations

from django.templatetags.static import static

from .models import MikroTikRouter


# Maps ModelChoice values -> static image path under static/img/mikrotik/
_IMAGE_FILES = {
    MikroTikRouter.ModelChoice.HAP_AX2: "img/mikrotik/hap_ax2.webp",
    MikroTikRouter.ModelChoice.HAP_AX3: "img/mikrotik/hap_ax3.webp",
    MikroTikRouter.ModelChoice.HAP_LITE: "img/mikrotik/hap_lite.webp",
    MikroTikRouter.ModelChoice.HAP_AC2: "img/mikrotik/hap_ac2.webp",
    MikroTikRouter.ModelChoice.HAP_AC3: "img/mikrotik/hap_ac3.webp",
    MikroTikRouter.ModelChoice.HEX: "img/mikrotik/rb750gr3.webp",
    MikroTikRouter.ModelChoice.HEX_S: "img/mikrotik/rb760igs.webp",
    MikroTikRouter.ModelChoice.L009: "img/mikrotik/l009.webp",
    MikroTikRouter.ModelChoice.RB951: "img/mikrotik/hap_lite.webp",
    MikroTikRouter.ModelChoice.RB2011: "img/mikrotik/rb2011.webp",
    MikroTikRouter.ModelChoice.RB3011: "img/mikrotik/rb3011.webp",
    MikroTikRouter.ModelChoice.RB4011: "img/mikrotik/rb4011.webp",
    MikroTikRouter.ModelChoice.RB5009: "img/mikrotik/rb5009.webp",
    MikroTikRouter.ModelChoice.CCR2004: "img/mikrotik/ccr2004.webp",
    MikroTikRouter.ModelChoice.CCR2116: "img/mikrotik/ccr2116.webp",
    MikroTikRouter.ModelChoice.CCR2216: "img/mikrotik/ccr2216.webp",
    MikroTikRouter.ModelChoice.CHR: "img/mikrotik/chr.svg",
    MikroTikRouter.ModelChoice.AUDIENCE: "img/mikrotik/audience.webp",
    MikroTikRouter.ModelChoice.OTHER: "img/mikrotik/other.svg",
}

_cached_catalog: list[dict] | None = None


def mikrotik_model_image(model_value: str) -> str:
    """Static URL for a MikroTik model thumbnail."""
    image_path = _IMAGE_FILES.get(model_value, "img/mikrotik/other.svg")
    return static(image_path)


def mikrotik_model_catalog() -> list[dict]:
    """Choices with short labels and image URLs for the visual model picker."""
    global _cached_catalog
    # Rebuild when choice set changes (e.g. new model added).
    expected = len(MikroTikRouter.ModelChoice.choices)
    if _cached_catalog is not None and len(_cached_catalog) == expected:
        return _cached_catalog

    catalog = []
    for value, label in MikroTikRouter.ModelChoice.choices:
        catalog.append(
            {
                "value": value,
                "label": label,
                "image": mikrotik_model_image(value),
            }
        )
    _cached_catalog = catalog
    return catalog
