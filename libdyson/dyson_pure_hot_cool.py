"""Dyson Pure Hot+Cool device."""

from .dyson_device import DysonHeatingDevice
from .dyson_pure_cool import DysonPureCool


class DysonPureHotCool(DysonPureCool, DysonHeatingDevice):
    """Dyson Pure Hot+Cool device."""


class DysonPurifierHotCoolFormaldehyde(DysonPureHotCool):
    """Dyson Pure Hot+Cool Formaldehyde device."""

    @property
    def formaldehyde(self):
        """Return formaldehyde reading."""
        return int(self._get_environmental_field_value("hcho"))
