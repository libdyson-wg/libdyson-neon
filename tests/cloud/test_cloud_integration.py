"""Integration tests for cloud module."""

from unittest.mock import patch

import pytest
import requests

from libdyson.cloud import DysonAccount
from libdyson.cloud.device_info import DysonDeviceInfo
from libdyson.cloud.cloud_360_eye import DysonCloud360Eye
from libdyson.cloud.account import (
    API_PATH_PROVISION_APP,
    API_PATH_DEVICES,
    API_PATH_USER_STATUS,
    API_PATH_EMAIL_REQUEST,
    API_PATH_EMAIL_VERIFY,
)
from libdyson.exceptions import (
    DysonNetworkError,
    DysonServerError,
    DysonAuthRequired,
)

from . import AUTH_INFO
from .mocked_requests import MockedRequests

# Test constants
EMAIL = "test@example.com"
REGION = "US"
CHALLENGE_ID = "test-challenge-id"


def test_full_device_retrieval_flow(mocked_requests):
    """Test complete device retrieval flow."""
    account = DysonAccount(AUTH_INFO)
    
    # Mock all required endpoints
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def devices_handler(**kwargs):
        return (200, [
            {
                "Active": True,
                "Serial": "ABC-123-DEF",
                "Name": "Test Device",
                "Version": "438MPF.00.01.003.0011",
                "LocalCredentials": "encrypted_password",
                "AutoUpdate": True,
                "NewVersionAvailable": False,
                "ProductType": "438",
                "variant": "M",
            },
            {
                "Active": False,
                "Serial": "XYZ-789-GHI",
                "Name": "Test Device 2",
                "Version": "527KPF.01.02.003.0001",
                "LocalCredentials": "encrypted_password2",
                "AutoUpdate": False,
                "NewVersionAvailable": True,
                "ProductType": "527",
                "variant": "K",
            }
        ])
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, devices_handler)
    
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        mock_decrypt.side_effect = lambda x: f"decrypted_{x}"
        
        devices = account.devices()
        
        assert len(devices) == 2
        
        device1 = devices[0]
        assert device1.serial == "ABC-123-DEF"
        assert device1.get_device_type() == "438M"
        assert device1.active is True
        assert device1.auto_update is True
        assert device1.new_version_available is False
        
        device2 = devices[1]
        assert device2.serial == "XYZ-789-GHI"
        assert device2.get_device_type() == "527K"
        assert device2.active is False
        assert device2.auto_update is False
        assert device2.new_version_available is True


def test_device_filtering_no_credentials(mocked_requests):
    """Test devices without credentials are filtered out."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def devices_handler(**kwargs):
        return (200, [
            {
                "Active": True,
                "Serial": "ABC-123-DEF",
                "Name": "Device with credentials",
                "Version": "1.0.0",
                "LocalCredentials": "encrypted_password",
                "AutoUpdate": True,
                "NewVersionAvailable": False,
                "ProductType": "438",
            },
            {
                "Active": True,
                "Serial": "XYZ-456-GHI",
                "Name": "Device without credentials",
                "Version": "1.0.0",
                "LocalCredentials": None,
                "AutoUpdate": True,
                "NewVersionAvailable": False,
                "ProductType": "438",
            }
        ])
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, devices_handler)
    
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        mock_decrypt.return_value = "decrypted_password"
        
        devices = account.devices()
        
        assert len(devices) == 1
        assert devices[0].serial == "ABC-123-DEF"


def test_device_creation_error_handling(mocked_requests):
    """Test error handling during device creation."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def devices_handler(**kwargs):
        return (200, [
            {
                "Active": True,
                "Serial": "VALID-DEVICE",
                "Name": "Valid device",
                "Version": "1.0.0",
                "LocalCredentials": "valid_credentials",
                "AutoUpdate": True,
                "NewVersionAvailable": False,
                "ProductType": "438",
            },
            {
                "Active": True,
                "Serial": "INVALID-DEVICE",
                "Name": "Invalid device",
                "Version": "1.0.0",
                "LocalCredentials": "invalid_credentials",
                "AutoUpdate": True,
                "NewVersionAvailable": False,
                "ProductType": "438",
            }
        ])
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, devices_handler)
    
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        def side_effect(creds):
            if creds == "invalid_credentials":
                raise Exception("Decryption failed")
            return "decrypted_password"
        
        mock_decrypt.side_effect = side_effect
        
        # Should handle exception gracefully and return valid devices only
        devices = account.devices()
        assert len(devices) == 1
        assert devices[0].serial == "VALID-DEVICE"


def test_full_login_and_device_flow(mocked_requests):
    """Test complete login and device retrieval flow."""
    account = DysonAccount()
    email = "test@example.com"
    region = "GB"
    otp = "123456"
    password = "test_password"
    
    # Mock all login endpoints
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def user_status_handler(**kwargs):
        return (200, {"accountStatus": "ACTIVE"})
    
    def email_request_handler(**kwargs):
        return (200, {"challengeId": "test-challenge"})
    
    def email_verify_handler(**kwargs):
        return (200, {
            "token": "bearer_token",
            "tokenType": "Bearer",
            "account": "test_account"
        })
    
    def devices_handler(**kwargs):
        return (200, [
            {
                "Active": True,
                "Serial": "LOGIN-TEST-DEVICE",
                "Name": "Login Test Device",
                "Version": "1.0.0",
                "LocalCredentials": "encrypted_creds",
                "AutoUpdate": True,
                "NewVersionAvailable": False,
                "ProductType": "N223",
            }
        ])
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("POST", API_PATH_USER_STATUS, user_status_handler)
    mocked_requests.register_handler("POST", API_PATH_EMAIL_REQUEST, email_request_handler)
    mocked_requests.register_handler("POST", API_PATH_EMAIL_VERIFY, email_verify_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, devices_handler)
    
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        mock_decrypt.return_value = "decrypted_password"
        
        # Login
        verify_func = account.login_email_otp(email, region)
        auth_info = verify_func(otp, password)
        
        assert auth_info["token"] == "bearer_token"
        assert account.auth_info == auth_info
        
        # Get devices
        devices = account.devices()
        
        assert len(devices) == 1
        assert devices[0].serial == "LOGIN-TEST-DEVICE"


def test_cloud_360_eye_integration(mocked_requests):
    """Test 360 Eye cloud integration."""
    account = DysonAccount(AUTH_INFO)
    serial = "360-EYE-SERIAL"
    device = DysonCloud360Eye(account, serial)
    
    # Mock cleaning history
    def cleaning_history_handler(**kwargs):
        return (200, {
            "Entries": [
                {
                    "Clean": "cleaning-1",
                    "Started": "2021-02-09T12:00:00",
                    "Finished": "2021-02-09T13:00:00",
                    "Area": 25.0,
                    "Charges": 1,
                    "Type": "Immediate",
                    "IsInterim": False,
                }
            ]
        })
    
    # Mock cleaning map
    def cleaning_map_handler(**kwargs):
        return (200, b"PNG_MAP_DATA")
    
    mocked_requests.register_handler(
        "GET", f"/v1/assets/devices/{serial}/cleanhistory", cleaning_history_handler
    )
    mocked_requests.register_handler(
        "GET", f"/v1/mapvisualizer/devices/{serial}/map/cleaning-1", cleaning_map_handler
    )
    
    # Test cleaning history
    tasks = device.get_cleaning_history()
    assert len(tasks) == 1
    assert tasks[0].cleaning_id == "cleaning-1"
    
    # Test cleaning map
    map_data = device.get_cleaning_map("cleaning-1")
    assert map_data == b"PNG_MAP_DATA"


def test_network_error_propagation(mocked_requests):
    """Test that network errors are properly propagated through the stack."""
    account = DysonAccount(AUTH_INFO)
    
    def network_error_handler(**kwargs):
        raise requests.RequestException("Network connection failed")
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, network_error_handler)
    
    with pytest.raises(DysonNetworkError):
        account.devices()


def test_server_error_propagation(mocked_requests):
    """Test that server errors are properly propagated through the stack."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def server_error_handler(**kwargs):
        return (500, {"error": "Internal server error"})
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, server_error_handler)
    
    with pytest.raises(DysonServerError):
        account.devices()


def test_auth_required_propagation():
    """Test that auth required errors are properly propagated."""
    account = DysonAccount()  # No auth info
    
    with pytest.raises(DysonAuthRequired):
        account.devices()


def test_device_variant_detection_integration(mocked_requests):
    """Test device variant detection integration."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def devices_handler(**kwargs):
        return (200, [
            {
                "Active": True,
                "Serial": "VARIANT-TEST-1",
                "Name": "Explicit Variant Device",
                "Version": "1.0.0",
                "LocalCredentials": "encrypted1",
                "AutoUpdate": True,
                "NewVersionAvailable": False,
                "ProductType": "438",
                "variant": "M",
            },
            {
                "Active": True,
                "Serial": "VARIANT-TEST-2",
                "Name": "Firmware Variant Device",
                "Version": "527KPF.01.02.003.0001",
                "LocalCredentials": "encrypted2",
                "AutoUpdate": True,
                "NewVersionAvailable": False,
                "ProductType": "527",
                # No variant field - should extract from firmware
            },
            {
                "Active": True,
                "Serial": "VARIANT-TEST-3",
                "Name": "No Variant Device",
                "Version": "1.0.0",
                "LocalCredentials": "encrypted3",
                "AutoUpdate": True,
                "NewVersionAvailable": False,
                "ProductType": "N223",
                # No variant needed for this device type
            }
        ])
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, devices_handler)
    
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        mock_decrypt.side_effect = lambda x: f"decrypted_{x}"
        
        devices = account.devices()
        
        assert len(devices) == 3
        
        # Explicit variant
        assert devices[0].get_device_type() == "438M"
        
        # Firmware-extracted variant
        assert devices[1].get_device_type() == "527K"
        
        # No variant needed
        from libdyson.const import DEVICE_TYPE_360_EYE
        assert devices[2].get_device_type() == DEVICE_TYPE_360_EYE


def test_mixed_success_failure_scenarios(mocked_requests):
    """Test scenarios with mixed success and failure responses."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    call_count = 0
    def devices_handler(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First call fails
            return (500, {"error": "Server error"})
        else:
            # Subsequent calls succeed
            return (200, [
                {
                    "Active": True,
                    "Serial": "RETRY-SUCCESS",
                    "Name": "Retry Success Device",
                    "Version": "1.0.0",
                    "LocalCredentials": "encrypted",
                    "AutoUpdate": True,
                    "NewVersionAvailable": False,
                    "ProductType": "438",
                }
            ])
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, devices_handler)
    
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        mock_decrypt.return_value = "decrypted_password"
        
        # The call should succeed after retry (not fail)
        with patch('time.sleep'):  # Speed up the test
            devices = account.devices()
            assert len(devices) == 1
            assert devices[0].name == "Retry Success Device"
            assert devices[0].serial == "RETRY-SUCCESS"
            
        # Verify that the handler was called twice (initial + retry)
        assert call_count == 2


def test_comprehensive_error_scenarios(mocked_requests):
    """Test comprehensive error handling across the entire flow."""
    
    # Test each potential failure point
    failure_points = [
        ("provision", API_PATH_PROVISION_APP, lambda **kwargs: (404, None)),
        ("devices", API_PATH_DEVICES, lambda **kwargs: (401, {"error": "Unauthorized"})),
        ("network", API_PATH_DEVICES, lambda **kwargs: Exception("Network error")),
    ]
    
    for failure_name, endpoint, handler in failure_points:
        account = DysonAccount(AUTH_INFO)
        
        if failure_name != "provision":
            # Provision needs to succeed for other tests
            def provision_handler(**kwargs):
                return (200, '"5.0.21061"')
            mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
        
        mocked_requests.register_handler("GET", endpoint, handler)
        
        with pytest.raises((DysonNetworkError, DysonServerError, Exception)):
            account.devices()
        
        # Clear handlers for next iteration
        mocked_requests._handlers.clear()


def test_account_devices_with_malformed_response(mocked_requests):
    """Test devices method with malformed API response."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def devices_handler(**kwargs):
        # Return malformed response (not a list)
        return (200, {"error": "This should be a list"})
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, devices_handler)
    
    # Should handle malformed response gracefully
    with pytest.raises(Exception):  # Will raise when trying to iterate over dict
        account.devices()


def test_account_devices_with_partial_device_data(mocked_requests):
    """Test devices method with partial device data."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def devices_handler(**kwargs):
        return (200, [
            {
                # Missing many fields but including required ones
                "Serial": "ABC-123-DEF",
                "Name": "Partial Device",
                "Version": "1.0.0",
                "LocalCredentials": "valid_credentials",
                "ProductType": "438",
                "AutoUpdate": True,
                "NewVersionAvailable": False,
            }
        ])
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, devices_handler)
    
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        mock_decrypt.return_value = "decrypted_password"
        
        devices = account.devices()
        assert len(devices) == 1
        assert devices[0].serial == "ABC-123-DEF"
        assert devices[0].name == "Partial Device"
        assert devices[0].active is None  # Missing Active field should be None


def test_account_devices_variant_field_detection(mocked_requests):
    """Test devices method with variant field detection."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def devices_handler(**kwargs):
        return (200, [
            {
                "Active": True,
                "Serial": "ABC-123-DEF",
                "Name": "Device with variant",
                "Version": "1.0.0",
                "LocalCredentials": "valid_credentials",
                "ProductType": "438",
                "AutoUpdate": True,
                "NewVersionAvailable": False,
                "variant": "M",  # Explicit variant field
            }
        ])
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, devices_handler)
    
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        mock_decrypt.return_value = "decrypted_password"
        
        devices = account.devices()
        assert len(devices) == 1
        assert devices[0].serial == "ABC-123-DEF"


def test_account_devices_alternative_variant_fields(mocked_requests):
    """Test devices method with alternative variant field names."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def devices_handler(**kwargs):
        return (200, [
            {
                "Active": True,
                "Serial": "ABC-123-DEF",
                "Name": "Device with ProductVariant",
                "Version": "1.0.0",
                "LocalCredentials": "valid_credentials",
                "ProductType": "438",
                "AutoUpdate": True,
                "NewVersionAvailable": False,
                "ProductVariant": "K",  # Alternative variant field name
            }
        ])
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, devices_handler)
    
    with patch('libdyson.cloud.device_info.decrypt_password') as mock_decrypt:
        mock_decrypt.return_value = "decrypted_password"
        
        devices = account.devices()
        assert len(devices) == 1
        assert devices[0].serial == "ABC-123-DEF"


def test_account_login_email_with_network_retry(mocked_requests):
    """Test email login with network retry scenarios using the retry request method."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    request_count = 0
    def test_handler(**kwargs):
        nonlocal request_count
        request_count += 1
        if request_count == 1:
            return (500, {"error": "Server error"})  # First call fails
        return (200, {"success": True})  # Second call succeeds
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", "/test-retry", test_handler)
    
    with patch('time.sleep'):  # Speed up the test
        # Test the retry request directly
        response = account._retry_request("GET", "/test-retry", max_retries=3)
        assert response.status_code == 200
        assert request_count == 2  # Initial failure + retry
