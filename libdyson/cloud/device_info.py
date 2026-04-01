"""Dyson device info."""

from typing import Optional

import attr

from ..const import (  # noqa: F401
    DEVICE_TYPE_360_EYE,
    DEVICE_TYPE_360_HEURIST,
    DEVICE_TYPE_360_VIS_NAV,
    DEVICE_TYPE_PURE_COOL,
    DEVICE_TYPE_PURE_COOL_DESK,
    DEVICE_TYPE_PURE_COOL_LINK,
    DEVICE_TYPE_PURE_COOL_LINK_DESK,
    DEVICE_TYPE_PURE_HOT_COOL,
    DEVICE_TYPE_PURE_HOT_COOL_LINK,
    DEVICE_TYPE_PURE_HUMIDIFY_COOL,
    DEVICE_TYPE_PURIFIER_BIG_QUIET,
    DEVICE_TYPE_PURIFIER_COOL_E,
    DEVICE_TYPE_PURIFIER_COOL_K,
    DEVICE_TYPE_PURIFIER_COOL_M,
    DEVICE_TYPE_PURIFIER_HOT_COOL_E,
    DEVICE_TYPE_PURIFIER_HOT_COOL_K,
    DEVICE_TYPE_PURIFIER_HOT_COOL_M,
    DEVICE_TYPE_PURIFIER_HUMIDIFY_COOL_E,
    DEVICE_TYPE_PURIFIER_HUMIDIFY_COOL_K,
)
from .utils import decrypt_password

# Mapping from cloud API ProductType to internal device type codes.
#
# IMPORTANT: Variant-specific entries (438K, 438E, 438M, 527K, etc.) MUST map
# to their variant-specific constants (DEVICE_TYPE_PURIFIER_COOL_K, etc.), NOT
# to the base type (DEVICE_TYPE_PURE_COOL). The device_type string is used
# directly as the MQTT topic prefix (e.g. "438K/{serial}/status/current"), and
# devices with variant suffixes only respond on their variant-prefixed topics.
CLOUD_PRODUCT_TYPE_TO_DEVICE_TYPE = {
    # 360 Eye robot vacuum
    "360 Eye": DEVICE_TYPE_360_EYE,
    "360EYE": DEVICE_TYPE_360_EYE,
    "N223": DEVICE_TYPE_360_EYE,
    # 360 Heurist robot vacuum
    "360 Heurist": DEVICE_TYPE_360_HEURIST,
    "360HEURIST": DEVICE_TYPE_360_HEURIST,
    "276": DEVICE_TYPE_360_HEURIST,
    # 360 Vis Nav robot vacuum
    "360 Vis Nav": DEVICE_TYPE_360_VIS_NAV,
    "360VIS": DEVICE_TYPE_360_VIS_NAV,
    "277": DEVICE_TYPE_360_VIS_NAV,
    # Pure Cool Link models
    "TP02": DEVICE_TYPE_PURE_COOL_LINK,
    "TP01": DEVICE_TYPE_PURE_COOL_LINK,
    "DP01": DEVICE_TYPE_PURE_COOL_LINK_DESK,
    "DP02": DEVICE_TYPE_PURE_COOL_LINK_DESK,
    "475": DEVICE_TYPE_PURE_COOL_LINK,
    "469": DEVICE_TYPE_PURE_COOL_LINK_DESK,
    # Pure Cool models
    "TP04": DEVICE_TYPE_PURE_COOL,
    "AM06": DEVICE_TYPE_PURE_COOL_DESK,
    "438": DEVICE_TYPE_PURE_COOL,
    "520": DEVICE_TYPE_PURE_COOL_DESK,
    # Purifier Cool models (newer) - base type for model names without variant info
    "TP07": DEVICE_TYPE_PURE_COOL,
    "TP09": DEVICE_TYPE_PURE_COOL,
    "TP11": DEVICE_TYPE_PURE_COOL,
    "PC1": DEVICE_TYPE_PURE_COOL,
    # Variant-specific Cool series - preserve variant for MQTT topic prefix
    "438K": DEVICE_TYPE_PURIFIER_COOL_K,
    "438E": DEVICE_TYPE_PURIFIER_COOL_E,
    "438M": DEVICE_TYPE_PURIFIER_COOL_M,
    # Pure Hot+Cool Link models
    "HP02": DEVICE_TYPE_PURE_HOT_COOL_LINK,
    "455": DEVICE_TYPE_PURE_HOT_COOL_LINK,
    # Pure Hot+Cool models
    "HP04": DEVICE_TYPE_PURE_HOT_COOL,
    "527": DEVICE_TYPE_PURE_HOT_COOL,
    # Purifier Hot+Cool models (newer) - base type for model names without variant info
    "HP07": DEVICE_TYPE_PURE_HOT_COOL,
    "HP09": DEVICE_TYPE_PURE_HOT_COOL,
    # Variant-specific Hot+Cool series - preserve variant for MQTT topic prefix
    "527K": DEVICE_TYPE_PURIFIER_HOT_COOL_K,
    "527E": DEVICE_TYPE_PURIFIER_HOT_COOL_E,
    "527M": DEVICE_TYPE_PURIFIER_HOT_COOL_M,
    # Pure Humidify+Cool models
    "PH01": DEVICE_TYPE_PURE_HUMIDIFY_COOL,
    "PH02": DEVICE_TYPE_PURE_HUMIDIFY_COOL,
    "358": DEVICE_TYPE_PURE_HUMIDIFY_COOL,
    # Purifier Humidify+Cool models (newer) - base type for model names without variant info
    "PH03": DEVICE_TYPE_PURE_HUMIDIFY_COOL,
    "PH04": DEVICE_TYPE_PURE_HUMIDIFY_COOL,
    # Variant-specific Humidify+Cool series - preserve variant for MQTT topic prefix
    "358K": DEVICE_TYPE_PURIFIER_HUMIDIFY_COOL_K,
    "358E": DEVICE_TYPE_PURIFIER_HUMIDIFY_COOL_E,
    # Purifier Big+Quiet models
    "BP02": DEVICE_TYPE_PURIFIER_BIG_QUIET,
    "BP03": DEVICE_TYPE_PURIFIER_BIG_QUIET,
    "BP04": DEVICE_TYPE_PURIFIER_BIG_QUIET,
    "664": DEVICE_TYPE_PURIFIER_BIG_QUIET,
}


def map_product_type_to_device_type(
    product_type: str,
    serial: Optional[str] = None,
    variant: Optional[str] = None,
    name: Optional[str] = None,
) -> Optional[str]:
    """Map cloud API ProductType to internal device type code.

    Args:
        product_type: The ProductType from the cloud API
        serial: Device serial number (optional, for logging)
        variant: The variant field from the cloud API (optional)
        name: Device name (optional, for logging)

    Returns:
        Internal device type code or None if unknown

    Note:
        For devices that require variant-specific MQTT topics (like 438K, 527K, etc.),
        this function returns the variant-specific type code to ensure the correct
        MQTT topic prefix is used for communication with the device.
    """
    import logging

    _LOGGER = logging.getLogger(__name__)

    _LOGGER.debug(
        "Mapping ProductType: '%s' (variant: %s, serial: %s)",
        product_type,
        variant,
        serial,
    )

    if not product_type:
        _LOGGER.debug("Empty product_type, returning None")
        return None

    # For devices with explicit variants that affect MQTT topics, prefer variant-specific mapping
    if variant is not None and variant.strip():
        variant_upper = variant.upper()

        # Check for variant combinations first (like 438M, 527K, etc.)
        # These devices need the variant in their MQTT topics
        if product_type in ["438", "527", "358"]:
            combined_type = product_type + variant_upper

            if combined_type in CLOUD_PRODUCT_TYPE_TO_DEVICE_TYPE:
                _LOGGER.debug(
                    "Using variant-specific device type: %s", combined_type
                )
                return CLOUD_PRODUCT_TYPE_TO_DEVICE_TYPE[combined_type]

        # Try direct variant mapping
        if variant_upper in CLOUD_PRODUCT_TYPE_TO_DEVICE_TYPE:
            mapped_type = CLOUD_PRODUCT_TYPE_TO_DEVICE_TYPE[variant_upper]
            _LOGGER.debug("Found variant mapping: %s -> %s", variant_upper, mapped_type)
            return mapped_type

    # Direct mapping for product types
    if product_type in CLOUD_PRODUCT_TYPE_TO_DEVICE_TYPE:
        mapped_type = CLOUD_PRODUCT_TYPE_TO_DEVICE_TYPE[product_type]
        _LOGGER.debug("Found direct mapping: %s -> %s", product_type, mapped_type)
        return mapped_type

    _LOGGER.warning(
        "No mapping found for ProductType: %s, variant: %s",
        product_type,
        variant,
    )
    return None


@attr.s(auto_attribs=True, frozen=True)
class DysonDeviceInfo:
    """Dyson device info."""

    active: Optional[bool]
    serial: str
    name: str
    version: str
    credential: str
    auto_update: bool
    new_version_available: bool
    product_type: str
    variant: Optional[str] = None

    @classmethod
    def from_raw(cls, raw: dict):
        """Parse raw data."""
        import logging

        _LOGGER = logging.getLogger(__name__)

        product_type = raw.get("ProductType", "")
        variant = raw.get("variant")
        version = raw.get("Version", "")

        _LOGGER.debug(
            "DysonDeviceInfo.from_raw: ProductType='%s', variant='%s', Serial='%s'",
            product_type,
            variant,
            raw.get("Serial", ""),
        )

        # Extract variant from firmware version when not provided by the cloud API.
        # Firmware format: {ProductType}{Variant}{ProductCategory}.{VersionInfo}
        # Examples:
        # - 438MPF.00.01.003.0011 -> variant "M"
        # - 527KPF.01.02.003.0001 -> variant "K"
        # - 358EPF.02.01.004.0005 -> variant "E"
        if product_type in ["438", "527", "358"] and (
            variant is None or not variant.strip()
        ):
            if version and len(version) >= 4:
                firmware_prefix = version[:4]
                if (
                    firmware_prefix.startswith(product_type)
                    and len(firmware_prefix) == 4
                ):
                    potential_variant = firmware_prefix[3]
                    if potential_variant in ["M", "K", "E"]:
                        variant = potential_variant
                        _LOGGER.debug(
                            "Extracted variant '%s' from firmware version: %s",
                            variant,
                            version,
                        )

        return cls(
            raw["Active"] if "Active" in raw else None,
            raw["Serial"],
            raw["Name"],
            version,
            decrypt_password(raw["LocalCredentials"]),
            raw["AutoUpdate"],
            raw["NewVersionAvailable"],
            product_type,
            variant,
        )

    def get_device_type(self) -> Optional[str]:
        """Get the internal device type code from the cloud product type."""
        return map_product_type_to_device_type(
            self.product_type, self.serial, self.variant, self.name
        )
