"""Tests for DysonAccount."""

from typing import Optional, Tuple
import time
from unittest.mock import patch, MagicMock

import pytest
import requests
from requests.auth import AuthBase, HTTPBasicAuth

from libdyson.cloud import DysonAccount
from libdyson.cloud.account import (
    API_PATH_DEVICES,
    API_PATH_EMAIL_REQUEST,
    API_PATH_EMAIL_VERIFY,
    API_PATH_MOBILE_REQUEST,
    API_PATH_MOBILE_VERIFY,
    API_PATH_USER_STATUS,
    API_PATH_PROVISION_APP,
    DYSON_API_HOST_CN,
    DysonAccountCN,
    HTTPBearerAuth,
)
from libdyson.exceptions import (
    DysonAuthRequired,
    DysonInvalidAccountStatus,
    DysonInvalidAuth,
    DysonLoginFailure,
    DysonNetworkError,
    DysonOTPTooFrequently,
    DysonServerError,
    DysonAPIProvisionFailure,
)

from . import AUTH_ACCOUNT, AUTH_INFO, AUTH_PASSWORD
from .mocked_requests import MockedRequests
from .utils import encrypt_credential

EMAIL = "user@example.com"
PASSWORD = "password"
REGION = "GB"
MOBILE = "+8613588888888"
OTP = "000000"
CHALLENGE_ID = "2b289d7f-1e0d-41e2-a0cb-56115eab6855"

BEARER_TOKEN = "BEARER_TOKEN"
AUTH_INFO_BEARER = {
    "token": BEARER_TOKEN,
    "tokenType": "Bearer",
    "account": AUTH_ACCOUNT,
}

DEVICE1_SERIAL = "NK6-CN-HAA0000A"
DEVICE1_NAME = "Device1"
DEVICE1_VERSION = "10.01.01CN"
DEVICE1_PRODUCT_TYPE = "475"
DEVICE1_CREDENTIAL = "aoWJM1kpL79MN2dPMlL5ysQv/APG+HAv+x3HDk0yuT3gMfgA3mLuil4O3d+q6CcyU+D1Hoir38soKoZHshYFeQ=="

DEVICE2_SERIAL = "JH1-US-HBB1111A"
DEVICE2_NAME = "Device2"
DEVICE2_VERSION = "11.02.02"
DEVICE2_PRODUCT_TYPE = "N223"
DEVICE2_CREDENTIAL = "KVjUpJoKwK7E9FDe5LN5JbUqDEfEDh5PlcNC7GJH1Ib2gGEpXwKEFszORFS8+tL8CNlvZTRmsUhf+kS37B7qAg=="

DEVICES = [
    {
        "Active": True,
        "Serial": DEVICE1_SERIAL,
        "Name": DEVICE1_NAME,
        "Version": DEVICE1_VERSION,
        "LocalCredentials": encrypt_credential(
            DEVICE1_SERIAL,
            DEVICE1_CREDENTIAL,
        ),
        "AutoUpdate": True,
        "NewVersionAvailable": False,
        "ProductType": DEVICE1_PRODUCT_TYPE,
        "ConnectionType": "wss",
    },
    {
        "Serial": DEVICE2_SERIAL,
        "Name": DEVICE2_NAME,
        "Version": DEVICE2_VERSION,
        "LocalCredentials": encrypt_credential(
            DEVICE2_SERIAL,
            DEVICE2_CREDENTIAL,
        ),
        "AutoUpdate": False,
        "NewVersionAvailable": True,
        "ProductType": DEVICE2_PRODUCT_TYPE,
        "ConnectionType": "wss",
    },
    {
        "Serial": "YS4-EU-MCA0660A",
        "Name": "Device3",
        "Version": "13.80.22",
        "LocalCredentials": None,
        "AutoUpdate": True,
        "NewVersionAvailable": False,
        "ProductType": "552",
        "ConnectionType": "wss",
    },
]


def _app_provision_handler(
        params: dict, json: dict, auth: Optional[AuthBase], **kwargs
) -> Tuple[int, Optional[str]]:
    return 200, '"5.0.21061"'


def _app_provision_handler_error(
        params: dict, json: dict, auth: Optional[AuthBase], **kwargs
) -> Tuple[int, Optional[str]]:
    return 404, ''


@pytest.fixture(autouse=True)
def mocked_requests(mocked_requests: MockedRequests) -> MockedRequests:
    """Return mocked requests library."""

    def _user_status_handler(
        params: dict, json: dict, auth: Optional[AuthBase], **kwargs
    ) -> Tuple[int, Optional[dict]]:
        assert auth is None
        assert params == {"country": REGION}
        if json["email"] == EMAIL:
            return (200, {"accountStatus": "ACTIVE"})
        return (200, {"accountStatus": "UNREGISTERED"})

    def _email_request_handler(
        json: dict, auth: Optional[AuthBase], **kwargs
    ) -> Tuple[int, Optional[dict]]:
        assert auth is None
        assert json == {
            "email": EMAIL,
        }
        return (200, {"challengeId": CHALLENGE_ID})

    def _email_verify_handler(
        json: dict, auth: Optional[AuthBase], **kwargs
    ) -> Tuple[int, Optional[dict]]:
        assert auth is None
        assert json["email"] == EMAIL
        assert json["challengeId"] == CHALLENGE_ID
        if json["password"] == PASSWORD and json["otpCode"] == OTP:
            return (200, AUTH_INFO_BEARER)
        return (400, None)

    def _mobile_request_handler(
        json: dict, auth: Optional[AuthBase], **kwargs
    ) -> Tuple[int, Optional[dict]]:
        assert auth is None
        assert json == {
            "mobile": MOBILE,
        }
        return (200, {"challengeId": CHALLENGE_ID})

    def _mobile_verify_handler(
        json: dict, auth: Optional[AuthBase], **kwargs
    ) -> Tuple[int, Optional[dict]]:
        assert auth is None
        assert json["mobile"] == MOBILE
        assert json["challengeId"] == CHALLENGE_ID
        if json["otpCode"] == OTP:
            return (200, AUTH_INFO_BEARER)
        return (400, None)

    def _devices_handler(
        auth: Optional[AuthBase], **kwargs
    ) -> Tuple[int, Optional[dict]]:
        if (
            not isinstance(auth, HTTPBasicAuth)
            or auth.username != AUTH_ACCOUNT
            or auth.password != AUTH_PASSWORD
        ) and (not isinstance(auth, HTTPBearerAuth) or auth.token != BEARER_TOKEN):
            return (401, None)
        return (200, DEVICES)

    mocked_requests.register_handler("POST", API_PATH_USER_STATUS, _user_status_handler)
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, _app_provision_handler)
    mocked_requests.register_handler(
        "POST", API_PATH_EMAIL_REQUEST, _email_request_handler
    )
    mocked_requests.register_handler(
        "POST", API_PATH_EMAIL_VERIFY, _email_verify_handler
    )
    mocked_requests.register_handler(
        "POST", API_PATH_MOBILE_REQUEST, _mobile_request_handler
    )
    mocked_requests.register_handler(
        "POST", API_PATH_MOBILE_VERIFY, _mobile_verify_handler
    )
    mocked_requests.register_handler("GET", API_PATH_DEVICES, _devices_handler)
    return mocked_requests


def test_account_provision_api(mocked_requests: MockedRequests):
    account = DysonAccount()

    assert account.provision_api() is None

    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, _app_provision_handler_error)

    with pytest.raises(DysonAPIProvisionFailure):
        account.provision_api()

    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, _app_provision_handler)

def test_account():
    """Test account functionalities."""
    account = DysonAccount()

    # Incorrect email
    with pytest.raises(DysonInvalidAccountStatus):
        account.login_email_otp("unregistered@example.com", REGION)
    assert account.auth_info is None
    with pytest.raises(DysonAuthRequired):
        account.devices()

    # Incorrect password
    with pytest.raises(DysonLoginFailure):
        verify = account.login_email_otp(EMAIL, REGION)
        verify(OTP, "wrong_pass")
    assert account.auth_info is None

    # Incorrect OTP
    with pytest.raises(DysonLoginFailure):
        verify = account.login_email_otp(EMAIL, REGION)
        verify("999999", PASSWORD)
    assert account.auth_info is None

    # Login succeed
    verify = account.login_email_otp(EMAIL, REGION)
    verify(OTP, PASSWORD)
    assert account.auth_info == AUTH_INFO_BEARER

    # Devices
    devices = account.devices()
    assert devices[0].active is True
    assert devices[0].serial == DEVICE1_SERIAL
    assert devices[0].name == DEVICE1_NAME
    assert devices[0].version == DEVICE1_VERSION
    assert devices[0].credential == DEVICE1_CREDENTIAL
    assert devices[0].product_type == DEVICE1_PRODUCT_TYPE
    assert devices[0].auto_update is True
    assert devices[0].new_version_available is False
    assert devices[1].active is None
    assert devices[1].serial == DEVICE2_SERIAL
    assert devices[1].name == DEVICE2_NAME
    assert devices[1].version == DEVICE2_VERSION
    assert devices[1].credential == DEVICE2_CREDENTIAL
    assert devices[1].product_type == DEVICE2_PRODUCT_TYPE
    assert devices[1].auto_update is False
    assert devices[1].new_version_available is True


def test_account_auth_info():
    """Test initialize account with auth info."""
    account = DysonAccount(AUTH_INFO)
    devices = account.devices()
    assert len(devices) == 2

    # Invalid auth
    account = DysonAccount(
        {
            "Account": "invalid",
            "Password": "invalid",
        },
    )
    with pytest.raises(DysonInvalidAuth):
        account.devices()

    # No auth
    account = DysonAccount()
    with pytest.raises(DysonAuthRequired):
        account.devices()


def test_login_email_request_too_frequently(mocked_requests: MockedRequests):
    """Test request for otp code too frequently."""

    def _handle_email_request(
        json: dict, auth: Optional[AuthBase], **kwargs
    ) -> Tuple[int, Optional[dict]]:
        assert auth is None
        return (429, None)

    mocked_requests.register_handler(
        "POST", API_PATH_EMAIL_REQUEST, _handle_email_request
    )

    account = DysonAccount()
    with pytest.raises(DysonOTPTooFrequently):
        account.login_email_otp(EMAIL, REGION)


def test_login_mobile(mocked_requests: MockedRequests):
    """Test logging into account using phone number and otp code."""
    mocked_requests.host = DYSON_API_HOST_CN

    account = DysonAccountCN()
    verify = account.login_mobile_otp(MOBILE)

    # Incorrect OTP
    with pytest.raises(DysonLoginFailure):
        verify("111111")
    assert account.auth_info is None

    # Correct OTP
    verify(OTP)
    assert account.auth_info == AUTH_INFO_BEARER
    account.devices()


def test_login_mobile_request_too_frequently(mocked_requests: MockedRequests):
    """Test request for otp code too frequently."""

    def _handle_mobile_request(
        json: dict, auth: Optional[AuthBase], **kwargs
    ) -> Tuple[int, Optional[dict]]:
        assert auth is None
        return (429, None)

    mocked_requests.host = DYSON_API_HOST_CN
    mocked_requests.register_handler(
        "POST", API_PATH_MOBILE_REQUEST, _handle_mobile_request
    )

    account = DysonAccountCN()
    with pytest.raises(DysonOTPTooFrequently):
        account.login_mobile_otp(MOBILE)


def test_account_auth_info_bearer(mocked_requests: MockedRequests):
    """Test initialize account with bearer auth info."""
    mocked_requests.host = DYSON_API_HOST_CN
    account = DysonAccountCN(AUTH_INFO_BEARER)
    devices = account.devices()
    assert len(devices) == 2

    # Old auth
    account = DysonAccountCN(AUTH_INFO)
    devices = account.devices()
    assert len(devices) == 2

    # Invalid auth
    account = DysonAccountCN(
        {
            "token": "invalid",
            "tokenType": "Bearer",
            "account": "invalid",
        },
    )
    with pytest.raises(DysonInvalidAuth):
        account.devices()

    # No auth
    account = DysonAccountCN()
    with pytest.raises(DysonAuthRequired):
        account.devices()

    # Not supported auth info
    account = DysonAccountCN({"token": "TOKEN", "tokenType": "Custom"})
    with pytest.raises(DysonAuthRequired):
        account.devices()


def test_network_error(mocked_requests: MockedRequests):
    """Test network error handling."""

    def _handler_network_error(**kwargs):
        raise requests.RequestException

    mocked_requests.register_handler(
        "POST", API_PATH_EMAIL_REQUEST, _handler_network_error
    )
    mocked_requests.register_handler("GET", API_PATH_DEVICES, _handler_network_error)

    account = DysonAccount()
    with pytest.raises(DysonNetworkError):
        account.login_email_otp(EMAIL, REGION)
    account = DysonAccount(AUTH_INFO)
    with pytest.raises(DysonNetworkError):
        account.devices()


def test_server_error(mocked_requests: MockedRequests):
    """Test cloud server error handling."""

    def _handler_network_error(**kwargs):
        return (500, None)

    mocked_requests.register_handler(
        "POST", API_PATH_EMAIL_REQUEST, _handler_network_error
    )
    mocked_requests.register_handler("GET", API_PATH_DEVICES, _handler_network_error)

    account = DysonAccount()
    with pytest.raises(DysonServerError):
        account.login_email_otp(EMAIL, REGION)
    account = DysonAccount(AUTH_INFO)
    with pytest.raises(DysonServerError):
        account.devices()


def test_http_bearer_auth_equality():
    """Test HTTPBearerAuth equality methods."""
    auth1 = HTTPBearerAuth("token123")
    auth2 = HTTPBearerAuth("token123")
    auth3 = HTTPBearerAuth("different_token")
    
    assert auth1 == auth2
    assert auth1 != auth3
    assert auth1 != "not_auth_object"


def test_http_bearer_auth_call():
    """Test HTTPBearerAuth request modification."""
    auth = HTTPBearerAuth("test_token")
    
    class MockRequest:
        def __init__(self):
            self.headers = {}
    
    request = MockRequest()
    result = auth(request)
    
    assert result == request
    assert request.headers["Authorization"] == "Bearer test_token"


def test_account_request_auth_required():
    """Test request fails when auth is required but not provided."""
    account = DysonAccount()
    
    with pytest.raises(DysonAuthRequired):
        account.request("GET", "/test", auth=True)


def test_account_request_different_auth_types():
    """Test request with different auth types."""
    # Test with basic auth
    account = DysonAccount({"Account": "test", "Password": "pass"})
    assert isinstance(account._auth, HTTPBasicAuth)
    
    # Test with bearer auth
    account = DysonAccount({"token": "test_token", "tokenType": "Bearer"})
    assert isinstance(account._auth, HTTPBearerAuth)
    
    # Test with invalid auth info
    account = DysonAccount({"invalid": "auth"})
    assert account._auth is None


def test_account_request_error_handling(mocked_requests):
    """Test request error handling."""
    account = DysonAccount(AUTH_INFO)
    
    # Test network error
    def network_error_handler(**kwargs):
        raise requests.RequestException("Network error")
    
    mocked_requests.register_handler("GET", "/test", network_error_handler)
    
    with pytest.raises(DysonNetworkError):
        account.request("GET", "/test")
    
    # Test server error
    def server_error_handler(**kwargs):
        return (500, {"error": "Server error"})
    
    mocked_requests.register_handler("GET", "/test2", server_error_handler)
    
    with pytest.raises(DysonServerError):
        account.request("GET", "/test2")


def test_retry_request_success_after_failure(mocked_requests):
    """Test retry logic succeeds after initial failures."""
    account = DysonAccount(AUTH_INFO)
    call_count = 0
    
    def failing_then_success_handler(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count < 3:
            raise requests.RequestException("Network error")
        return (200, {"success": True})
    
    mocked_requests.register_handler("GET", "/test", failing_then_success_handler)
    
    with patch('time.sleep'):  # Speed up the test
        response = account._retry_request("GET", "/test", max_retries=3)
        assert response.status_code == 200
        assert call_count == 3


def test_retry_request_permanent_failure(mocked_requests):
    """Test retry logic with permanent failures."""
    account = DysonAccount(AUTH_INFO)
    
    def permanent_failure_handler(**kwargs):
        return (401, {"error": "Unauthorized"})
    
    mocked_requests.register_handler("GET", "/test", permanent_failure_handler)
    
    # Should not retry auth failures
    with pytest.raises(DysonInvalidAuth):
        account._retry_request("GET", "/test", max_retries=3)


def test_retry_request_max_retries_exceeded(mocked_requests):
    """Test retry logic when max retries is exceeded."""
    account = DysonAccount(AUTH_INFO)
    call_count = 0
    
    def always_failing_handler(**kwargs):
        nonlocal call_count
        call_count += 1
        raise requests.RequestException("Network error")
    
    mocked_requests.register_handler("GET", "/test", always_failing_handler)
    
    with patch('time.sleep'):  # Speed up the test
        with pytest.raises(DysonNetworkError):
            account._retry_request("GET", "/test", max_retries=3)
        assert call_count == 3


def test_provision_api_success(mocked_requests):
    """Test successful API provisioning."""
    account = DysonAccount()
    
    def provision_success_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_success_handler)
    
    # Should not raise exception
    account.provision_api()


def test_provision_api_failure(mocked_requests):
    """Test API provisioning failure."""
    account = DysonAccount()
    
    def provision_failure_handler(**kwargs):
        return (404, None)
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_failure_handler)
    
    with pytest.raises(DysonAPIProvisionFailure):
        account.provision_api()


def test_login_email_otp_retry_logic(mocked_requests):
    """Test retry logic in email OTP verification."""
    account = DysonAccount()
    
    # Mock provision API
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    # Mock user status and email request
    def user_status_handler(**kwargs):
        return (200, {"accountStatus": "ACTIVE"})
    
    def email_request_handler(**kwargs):
        return (200, {"challengeId": CHALLENGE_ID})
    
    verify_call_count = 0
    def verify_handler(**kwargs):
        nonlocal verify_call_count
        verify_call_count += 1
        if verify_call_count < 3:
            raise requests.RequestException("Network error")
        return (200, AUTH_INFO_BEARER)
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("POST", API_PATH_USER_STATUS, user_status_handler)
    mocked_requests.register_handler("POST", API_PATH_EMAIL_REQUEST, email_request_handler)
    mocked_requests.register_handler("POST", API_PATH_EMAIL_VERIFY, verify_handler)
    
    with patch('time.sleep'):  # Speed up the test
        verify_func = account.login_email_otp(EMAIL, REGION)
        result = verify_func(OTP, PASSWORD)
        
        assert result == AUTH_INFO_BEARER
        assert verify_call_count == 3


def test_login_email_otp_auth_failure_no_retry(mocked_requests):
    """Test that auth failures are not retried in email OTP verification."""
    account = DysonAccount()
    
    # Mock provision API
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    # Mock user status and email request
    def user_status_handler(**kwargs):
        return (200, {"accountStatus": "ACTIVE"})
    
    def email_request_handler(**kwargs):
        return (200, {"challengeId": CHALLENGE_ID})
    
    verify_call_count = 0
    def verify_handler(**kwargs):
        nonlocal verify_call_count
        verify_call_count += 1
        return (401, {"error": "Invalid credentials"})
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("POST", API_PATH_USER_STATUS, user_status_handler)
    mocked_requests.register_handler("POST", API_PATH_EMAIL_REQUEST, email_request_handler)
    mocked_requests.register_handler("POST", API_PATH_EMAIL_VERIFY, verify_handler)
    
    verify_func = account.login_email_otp(EMAIL, REGION)
    
    with pytest.raises(DysonInvalidAuth):
        verify_func(OTP, PASSWORD)
    
    # Should only be called once (no retry)
    assert verify_call_count == 1


def test_devices_error_handling(mocked_requests):
    """Test error handling in devices retrieval."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def devices_error_handler(**kwargs):
        return (500, {"error": "Server error"})
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("GET", API_PATH_DEVICES, devices_error_handler)
    
    with pytest.raises(DysonServerError):
        account.devices()


def test_devices_logging_and_filtering(mocked_requests):
    """Test device logging and filtering logic."""
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
                "LocalCredentials": "valid_credentials",
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
        
        # Should filter out device without credentials
        assert len(devices) == 1
        assert devices[0].serial == "ABC-123-DEF"


def test_devices_exception_handling(mocked_requests):
    """Test exception handling during device creation."""
    account = DysonAccount(AUTH_INFO)
    
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def devices_handler(**kwargs):
        return (200, [
            {
                "Active": True,
                "Serial": "ABC-123-DEF",
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
        assert devices[0].serial == "ABC-123-DEF"
