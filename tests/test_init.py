"""Test Dyson Python library."""
from typing import Type

import pytest

from libdyson import (
    DEVICE_TYPE_360_EYE,
    DEVICE_TYPE_360_HEURIST,
    DEVICE_TYPE_PURE_COOL,
    DEVICE_TYPE_PURIFIER_COOL_E,
    DEVICE_TYPE_PURIFIER_COOL_K,
    DEVICE_TYPE_PURE_COOL_DESK,
    DEVICE_TYPE_PURE_COOL_LINK,
    DEVICE_TYPE_PURE_COOL_LINK_DESK,
    DEVICE_TYPE_PURE_HOT_COOL,
    DEVICE_TYPE_PURIFIER_HOT_COOL_E,
    DEVICE_TYPE_PURIFIER_HOT_COOL_K,
    DEVICE_TYPE_PURE_HOT_COOL_LINK,
    DEVICE_TYPE_PURE_HUMIDIFY_COOL,
    DEVICE_TYPE_PURIFIER_HUMIDIFY_COOL_E,
    DEVICE_TYPE_PURIFIER_HUMIDIFY_COOL_K,
    DEVICE_TYPE_PURIFIER_BIG_QUIET,
    Dyson360Eye,
    Dyson360Heurist,
    DysonDevice,
    DysonPureCool,
    DysonPureCoolLink,
    DysonPureHotCool,
    DysonPureHotCoolLink,
    DysonPurifierHumidifyCool,
    DysonBigQuiet,
    get_device,
)

from . import CREDENTIAL, SERIAL


@pytest.mark.parametrize(
    "device_type,class_type",
    [
        (DEVICE_TYPE_360_EYE, Dyson360Eye),
        (DEVICE_TYPE_360_HEURIST, Dyson360Heurist),
        (DEVICE_TYPE_PURE_COOL_LINK_DESK, DysonPureCoolLink),
        (DEVICE_TYPE_PURE_COOL_LINK, DysonPureCoolLink),
        (DEVICE_TYPE_PURE_COOL, DysonPureCool),
        (DEVICE_TYPE_PURIFIER_COOL_E, DysonPureCool),
        (DEVICE_TYPE_PURIFIER_COOL_K, DysonPureCool),
        (DEVICE_TYPE_PURE_COOL_DESK, DysonPureCool),
        (DEVICE_TYPE_PURE_HOT_COOL_LINK, DysonPureHotCoolLink),
        (DEVICE_TYPE_PURE_HOT_COOL, DysonPureHotCool),
        (DEVICE_TYPE_PURIFIER_HOT_COOL_E, DysonPureHotCool),
        (DEVICE_TYPE_PURIFIER_HOT_COOL_K, DysonPureHotCool),
        (DEVICE_TYPE_PURE_HUMIDIFY_COOL, DysonPurifierHumidifyCool),
        (DEVICE_TYPE_PURIFIER_HUMIDIFY_COOL_E, DysonPurifierHumidifyCool),
        (DEVICE_TYPE_PURIFIER_HUMIDIFY_COOL_K, DysonPurifierHumidifyCool),
        (DEVICE_TYPE_PURIFIER_BIG_QUIET, DysonBigQuiet),
    ],
)
def test_get_device(device_type: str, class_type: Type[DysonDevice]):
    """Test get_device."""
    device = get_device(SERIAL, CREDENTIAL, device_type)
    assert isinstance(device, class_type)
    assert device.serial == SERIAL


def test_get_device_unknown():
    """Test get_device with unknown type."""
    device = get_device(SERIAL, CREDENTIAL, "unknown")
    assert device is None
