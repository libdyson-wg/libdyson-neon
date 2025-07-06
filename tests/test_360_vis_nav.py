"""Tests for Dyson360VisNav."""

import pytest
from unittest.mock import MagicMock

from libdyson import Dyson360VisNav
from libdyson.const import DEVICE_TYPE_360_VIS_NAV

def test_dyson_360_vis_nav_device_type():
    """Test that Dyson360VisNav returns correct device type."""
    # Create a device with proper constructor arguments
    device = Dyson360VisNav("serial", "credential")
    
    # Test the device_type property
    assert device.device_type == DEVICE_TYPE_360_VIS_NAV


def test_dyson_360_vis_nav_inheritance():
    """Test that Dyson360VisNav properly inherits from Dyson360Heurist."""
    from libdyson.dyson_360_heurist import Dyson360Heurist
    
    device = Dyson360VisNav("serial", "credential")
    
    # Should inherit from Dyson360Heurist
    assert isinstance(device, Dyson360Heurist)
    
    # Should have all the parent class methods and properties
    assert hasattr(device, 'serial')
    assert device.serial == "serial"
    
    # Should have private attributes from base class
    assert hasattr(device, '_serial')
    assert hasattr(device, '_credential')
    assert device._serial == "serial"
    assert device._credential == "credential"
