"""Tests for DysonCloudDevice base class."""

import pytest

from libdyson.cloud import DysonAccount
from libdyson.cloud.cloud_device import DysonCloudDevice

from . import AUTH_INFO


def test_dyson_cloud_device_initialization():
    """Test DysonCloudDevice initialization."""
    account = DysonAccount(AUTH_INFO)
    serial = "TEST-SERIAL-123"
    
    device = DysonCloudDevice(account, serial)
    
    assert device._account == account
    assert device._serial == serial


def test_dyson_cloud_device_account_access():
    """Test access to account through cloud device."""
    account = DysonAccount(AUTH_INFO)
    serial = "TEST-SERIAL-123"
    
    device = DysonCloudDevice(account, serial)
    
    # Should be able to access account methods
    assert device._account.auth_info == AUTH_INFO


def test_dyson_cloud_device_serial_access():
    """Test access to serial through cloud device."""
    account = DysonAccount(AUTH_INFO)
    serial = "TEST-SERIAL-123"
    
    device = DysonCloudDevice(account, serial)
    
    assert device._serial == serial


def test_dyson_cloud_device_different_serials():
    """Test DysonCloudDevice with different serial formats."""
    account = DysonAccount(AUTH_INFO)
    
    test_serials = [
        "ABC-123-DEF",
        "XYZ-456-GHI-789",
        "SHORT",
        "VERY-LONG-SERIAL-NUMBER-WITH-MANY-PARTS",
        "123-456-789",
        "LETTERS-ONLY-SERIAL",
    ]
    
    for serial in test_serials:
        device = DysonCloudDevice(account, serial)
        assert device._serial == serial


def test_dyson_cloud_device_account_none():
    """Test DysonCloudDevice with None account."""
    serial = "TEST-SERIAL-123"
    
    device = DysonCloudDevice(None, serial)
    
    assert device._account is None
    assert device._serial == serial


def test_dyson_cloud_device_serial_none():
    """Test DysonCloudDevice with None serial."""
    account = DysonAccount(AUTH_INFO)
    
    device = DysonCloudDevice(account, None)
    
    assert device._account == account
    assert device._serial is None


def test_dyson_cloud_device_empty_serial():
    """Test DysonCloudDevice with empty serial."""
    account = DysonAccount(AUTH_INFO)
    serial = ""
    
    device = DysonCloudDevice(account, serial)
    
    assert device._account == account
    assert device._serial == ""


def test_dyson_cloud_device_unicode_serial():
    """Test DysonCloudDevice with unicode characters in serial."""
    account = DysonAccount(AUTH_INFO)
    serial = "TËST-SÉRÎÅL-123"
    
    device = DysonCloudDevice(account, serial)
    
    assert device._serial == serial


def test_dyson_cloud_device_inheritance():
    """Test that DysonCloudDevice can be inherited."""
    
    class TestCloudDevice(DysonCloudDevice):
        def test_method(self):
            return f"Device {self._serial} with account {self._account}"
    
    account = DysonAccount(AUTH_INFO)
    serial = "INHERIT-TEST"
    
    device = TestCloudDevice(account, serial)
    
    assert isinstance(device, DysonCloudDevice)
    assert device._serial == serial
    assert device._account == account
    assert "INHERIT-TEST" in device.test_method()


def test_dyson_cloud_device_multiple_instances():
    """Test multiple DysonCloudDevice instances."""
    account1 = DysonAccount(AUTH_INFO)
    account2 = DysonAccount({"different": "auth"})
    
    device1 = DysonCloudDevice(account1, "DEVICE-1")
    device2 = DysonCloudDevice(account2, "DEVICE-2")
    device3 = DysonCloudDevice(account1, "DEVICE-3")
    
    assert device1._account == account1
    assert device2._account == account2
    assert device3._account == account1
    
    assert device1._serial == "DEVICE-1"
    assert device2._serial == "DEVICE-2"
    assert device3._serial == "DEVICE-3"
    
    # Ensure instances are independent
    assert device1 != device2
    assert device1 != device3
    assert device2 != device3
