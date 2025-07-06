"""Tests for DysonDeviceInfo."""

from unittest.mock import patch

import pytest

from libdyson.cloud.device_info import (
    DysonDeviceInfo,
    map_product_type_to_device_type,
    CLOUD_PRODUCT_TYPE_TO_DEVICE_TYPE,
)
from libdyson.const import (
    DEVICE_TYPE_360_EYE,
    DEVICE_TYPE_PURE_COOL,
    DEVICE_TYPE_PURE_HOT_COOL,
    DEVICE_TYPE_PURE_HUMIDIFY_COOL,
    DEVICE_TYPE_PURIFIER_BIG_QUIET,
)


def test_map_product_type_to_device_type():
    """Test product type mapping."""
    # Test direct mapping
    assert map_product_type_to_device_type("N223") == DEVICE_TYPE_360_EYE
    assert map_product_type_to_device_type("438") == DEVICE_TYPE_PURE_COOL
    assert map_product_type_to_device_type("664") == DEVICE_TYPE_PURIFIER_BIG_QUIET
    
    # Test variant mapping
    assert map_product_type_to_device_type("438", variant="M") == "438M"
    assert map_product_type_to_device_type("527", variant="K") == "527K"
    assert map_product_type_to_device_type("358", variant="E") == "358E"
    
    # Test empty product type
    assert map_product_type_to_device_type("") is None
    assert map_product_type_to_device_type(None) is None
    
    # Test unknown product type
    assert map_product_type_to_device_type("UNKNOWN") is None


def test_map_product_type_variant_edge_cases():
    """Test variant mapping edge cases."""
    # Test empty variant
    assert map_product_type_to_device_type("438", variant="") == DEVICE_TYPE_PURE_COOL
    assert map_product_type_to_device_type("438", variant=None) == DEVICE_TYPE_PURE_COOL
    
    # Test whitespace variant
    assert map_product_type_to_device_type("438", variant="  ") == DEVICE_TYPE_PURE_COOL
    
    # Test case insensitive variant
    assert map_product_type_to_device_type("438", variant="m") == "438M"
    assert map_product_type_to_device_type("527", variant="k") == "527K"
    
    # Test unknown variant for variant-supporting device
    assert map_product_type_to_device_type("438", variant="X") == DEVICE_TYPE_PURE_COOL
    
    # Test variant on non-variant device
    assert map_product_type_to_device_type("N223", variant="M") == DEVICE_TYPE_360_EYE


def test_map_product_type_direct_variant_mapping():
    """Test direct variant mapping in lookup table."""
    # Test variants that exist directly in the mapping table
    assert map_product_type_to_device_type("438K") == DEVICE_TYPE_PURE_COOL
    assert map_product_type_to_device_type("527E") == DEVICE_TYPE_PURE_HOT_COOL
    assert map_product_type_to_device_type("358M") == DEVICE_TYPE_PURE_HUMIDIFY_COOL


def test_map_product_type_already_internal_type():
    """Test when product type is already an internal device type."""
    assert map_product_type_to_device_type(DEVICE_TYPE_360_EYE) == DEVICE_TYPE_360_EYE
    assert map_product_type_to_device_type(DEVICE_TYPE_PURE_COOL) == DEVICE_TYPE_PURE_COOL
    assert map_product_type_to_device_type(DEVICE_TYPE_PURIFIER_BIG_QUIET) == DEVICE_TYPE_PURIFIER_BIG_QUIET


def test_device_info_from_raw():
    """Test DysonDeviceInfo creation from raw data."""
    raw_data = {
        "Active": True,
        "Serial": "ABC-123-DEF",
        "Name": "Test Device",
        "Version": "1.0.0",
        "LocalCredentials": "encrypted_password",
        "AutoUpdate": True,
        "NewVersionAvailable": False,
        "ProductType": "438",
        "variant": "M",
    }
    
    # Mock the decrypt_password function
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        mock_decrypt.return_value = "decrypted_password"
        
        device_info = DysonDeviceInfo.from_raw(raw_data)
        
        assert device_info.active is True
        assert device_info.serial == "ABC-123-DEF"
        assert device_info.name == "Test Device"
        assert device_info.version == "1.0.0"
        assert device_info.credential == "decrypted_password"
        assert device_info.auto_update is True
        assert device_info.new_version_available is False
        assert device_info.product_type == "438"
        assert device_info.variant == "M"


def test_device_info_from_raw_missing_fields():
    """Test DysonDeviceInfo creation with missing optional fields."""
    raw_data = {
        "Serial": "ABC-123-DEF",
        "Name": "Test Device",
        "Version": "1.0.0",
        "LocalCredentials": "encrypted_password",
        "AutoUpdate": True,
        "NewVersionAvailable": False,
        "ProductType": "438",
        # Missing Active and variant fields
    }
    
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        mock_decrypt.return_value = "decrypted_password"
        
        device_info = DysonDeviceInfo.from_raw(raw_data)
        
        assert device_info.active is None
        assert device_info.variant is None
        assert device_info.serial == "ABC-123-DEF"


def test_device_info_from_raw_empty_version():
    """Test DysonDeviceInfo creation with empty version."""
    raw_data = {
        "Active": True,
        "Serial": "ABC-123-DEF",
        "Name": "Test Device",
        "Version": "",
        "LocalCredentials": "encrypted_password",
        "AutoUpdate": True,
        "NewVersionAvailable": False,
        "ProductType": "438",
    }
    
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        mock_decrypt.return_value = "decrypted_password"
        
        device_info = DysonDeviceInfo.from_raw(raw_data)
        assert device_info.version == ""


def test_device_info_get_device_type():
    """Test device type detection."""
    # Test with explicit variant
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="1.0.0",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="438",
        variant="M",
    )
    
    assert device_info.get_device_type() == "438M"


def test_device_info_get_device_type_no_variant():
    """Test device type detection without variant."""
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="1.0.0",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="438",
        variant=None,
    )
    
    assert device_info.get_device_type() == DEVICE_TYPE_PURE_COOL


def test_device_info_firmware_version_variant_extraction():
    """Test firmware version variant extraction."""
    # Test M variant extraction
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="438MPF.00.01.003.0011",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="438",
        variant=None,
    )
    
    assert device_info.get_device_type() == "438M"
    
    # Test K variant extraction
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="527KPF.01.02.003.0001",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="527",
        variant=None,
    )
    
    assert device_info.get_device_type() == "527K"
    
    # Test E variant extraction
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="358EPF.02.01.004.0005",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="358",
        variant=None,
    )
    
    assert device_info.get_device_type() == "358E"


def test_device_info_variant_extraction_edge_cases():
    """Test edge cases in variant extraction."""
    # Test invalid firmware version
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="short",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="438",
        variant=None,
    )
    
    assert device_info.get_device_type() == DEVICE_TYPE_PURE_COOL
    
    # Test invalid variant character
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="438XPF.00.01.003.0011",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="438",
        variant=None,
    )
    
    assert device_info.get_device_type() == DEVICE_TYPE_PURE_COOL
    
    # Test firmware that doesn't start with product type
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="999MPF.00.01.003.0011",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="438",
        variant=None,
    )
    
    assert device_info.get_device_type() == DEVICE_TYPE_PURE_COOL
    
    # Test empty firmware version
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="438",
        variant=None,
    )
    
    assert device_info.get_device_type() == DEVICE_TYPE_PURE_COOL


def test_device_info_variant_precedence():
    """Test that explicit variant takes precedence over firmware extraction."""
    # Explicit variant should override firmware version variant
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="438MPF.00.01.003.0011",  # Firmware suggests M variant
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="438",
        variant="K",  # Explicit K variant
    )
    
    assert device_info.get_device_type() == "438K"  # Should use explicit variant


def test_device_info_non_variant_product_types():
    """Test device types that don't support variants."""
    # Test 360 Eye
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="1.0.0",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="N223",
        variant="M",  # Should be ignored
    )
    
    assert device_info.get_device_type() == DEVICE_TYPE_360_EYE
    
    # Test Big+Quiet
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="1.0.0",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="664",
        variant="M",  # Should be ignored
    )
    
    assert device_info.get_device_type() == DEVICE_TYPE_PURIFIER_BIG_QUIET


def test_device_info_unknown_product_type():
    """Test unknown product type handling."""
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="1.0.0",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="UNKNOWN",
        variant=None,
    )
    
    assert device_info.get_device_type() is None


def test_device_info_immutable():
    """Test that DysonDeviceInfo is immutable."""
    device_info = DysonDeviceInfo(
        active=True,
        serial="ABC-123-DEF",
        name="Test Device",
        version="1.0.0",
        credential="password",
        auto_update=True,
        new_version_available=False,
        product_type="438",
        variant=None,
    )
    
    # Should not be able to modify fields (frozen=True)
    with pytest.raises(AttributeError):
        device_info.serial = "NEW-SERIAL"
