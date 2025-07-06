"""Tests for DysonAccountCN."""

from unittest.mock import patch

import pytest

from libdyson.cloud.account import (
    DysonAccountCN,
    DYSON_API_HOST_CN,
    API_PATH_MOBILE_REQUEST,
    API_PATH_MOBILE_VERIFY,
    API_PATH_PROVISION_APP,
)
from libdyson.exceptions import (
    DysonOTPTooFrequently,
    DysonLoginFailure,
    DysonAPIProvisionFailure,
)
from .mocked_requests import MockedRequests


def test_dyson_account_cn_host():
    """Test China account uses correct host."""
    account = DysonAccountCN()
    assert account._HOST == DYSON_API_HOST_CN


def test_dyson_account_cn_inheritance():
    """Test that DysonAccountCN inherits from DysonAccount."""
    from libdyson.cloud.account import DysonAccount
    
    account = DysonAccountCN()
    assert isinstance(account, DysonAccount)


def test_mobile_login_success(mocked_requests):
    """Test successful mobile login."""
    account = DysonAccountCN()
    challenge_id = "test-challenge-id"
    mobile = "+8613588888888"
    otp = "123456"
    
    # Mock provision API
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def mobile_request_handler(data=None, json=None, **kwargs):
        request_data = json or data
        assert request_data["mobile"] == mobile
        return (200, {"challengeId": challenge_id})
    
    def mobile_verify_handler(data=None, json=None, **kwargs):
        request_data = json or data
        assert request_data["mobile"] == mobile
        assert request_data["challengeId"] == challenge_id
        assert request_data["otpCode"] == otp
        return (200, {"token": "test-token", "tokenType": "Bearer"})
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_REQUEST, mobile_request_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_VERIFY, mobile_verify_handler)
    
    verify_func = account.login_mobile_otp(mobile)
    result = verify_func(otp)
    
    assert result["token"] == "test-token"
    assert result["tokenType"] == "Bearer"
    assert account.auth_info == result


def test_mobile_login_rate_limit(mocked_requests):
    """Test mobile login rate limiting."""
    account = DysonAccountCN()
    mobile = "+8613588888888"
    
    # Mock provision API
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def rate_limit_handler(**kwargs):
        return (429, None)
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_REQUEST, rate_limit_handler)
    
    with pytest.raises(DysonOTPTooFrequently):
        account.login_mobile_otp(mobile)


def test_mobile_login_invalid_credentials(mocked_requests):
    """Test mobile login with invalid credentials."""
    account = DysonAccountCN()
    challenge_id = "test-challenge-id"
    mobile = "+8613588888888"
    otp = "wrong-otp"
    
    # Mock provision API
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def mobile_request_handler(**kwargs):
        return (200, {"challengeId": challenge_id})
    
    def mobile_verify_handler(**kwargs):
        return (400, {"error": "Invalid OTP"})
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_REQUEST, mobile_request_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_VERIFY, mobile_verify_handler)
    
    verify_func = account.login_mobile_otp(mobile)
    
    with pytest.raises(DysonLoginFailure):
        verify_func(otp)


def test_mobile_login_provision_failure(mocked_requests):
    """Test mobile login when provision API fails."""
    account = DysonAccountCN()
    mobile = "+8613588888888"
    
    def provision_failure_handler(**kwargs):
        return (404, None)
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_failure_handler)
    
    with pytest.raises(DysonAPIProvisionFailure):
        account.login_mobile_otp(mobile)


def test_mobile_login_request_parameters(mocked_requests):
    """Test that mobile login sends correct request parameters."""
    account = DysonAccountCN()
    mobile = "+8613588888888"
    
    # Mock provision API
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    request_data = None
    def mobile_request_handler(data=None, json=None, **kwargs):
        nonlocal request_data
        request_data = json or data
        return (200, {"challengeId": "test-challenge"})
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_REQUEST, mobile_request_handler)
    
    account.login_mobile_otp(mobile)
    
    assert request_data is not None
    assert request_data["mobile"] == mobile


def test_mobile_verify_parameters(mocked_requests):
    """Test that mobile verify sends correct parameters."""
    account = DysonAccountCN()
    mobile = "+8613588888888"
    otp = "123456"
    challenge_id = "test-challenge-id"
    
    # Mock provision API
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def mobile_request_handler(**kwargs):
        return (200, {"challengeId": challenge_id})
    
    verify_data = None
    def mobile_verify_handler(data=None, json=None, **kwargs):
        nonlocal verify_data
        verify_data = json or data
        return (200, {"token": "test-token", "tokenType": "Bearer"})
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_REQUEST, mobile_request_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_VERIFY, mobile_verify_handler)
    
    verify_func = account.login_mobile_otp(mobile)
    verify_func(otp)
    
    assert verify_data is not None
    assert verify_data["mobile"] == mobile
    assert verify_data["challengeId"] == challenge_id
    assert verify_data["otpCode"] == otp


def test_mobile_login_auth_info_update(mocked_requests):
    """Test that auth info is properly updated after successful login."""
    account = DysonAccountCN()
    mobile = "+8613588888888"
    otp = "123456"
    expected_auth_info = {
        "token": "test-token",
        "tokenType": "Bearer",
        "account": "test-account"
    }
    
    # Mock provision API
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def mobile_request_handler(**kwargs):
        return (200, {"challengeId": "test-challenge"})
    
    def mobile_verify_handler(**kwargs):
        return (200, expected_auth_info)
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_REQUEST, mobile_request_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_VERIFY, mobile_verify_handler)
    
    # Initially no auth info
    assert account.auth_info is None
    
    verify_func = account.login_mobile_otp(mobile)
    result = verify_func(otp)
    
    # Auth info should be updated
    assert account.auth_info == expected_auth_info
    assert result == expected_auth_info


def test_mobile_login_different_mobile_formats(mocked_requests):
    """Test mobile login with different mobile number formats."""
    account = DysonAccountCN()
    
    # Mock provision API
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    test_numbers = [
        "+8613588888888",
        "13588888888",
        "+86 135 8888 8888",
        "135-8888-8888"
    ]
    
    for mobile in test_numbers:
        received_mobile = None
        
        def mobile_request_handler(data=None, json=None, **kwargs):
            nonlocal received_mobile
            request_data = json or data
            received_mobile = request_data["mobile"]
            return (200, {"challengeId": "test-challenge"})
        
        mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
        mocked_requests.register_handler("POST", API_PATH_MOBILE_REQUEST, mobile_request_handler)
        
        account.login_mobile_otp(mobile)
        
        # Should pass through the mobile number as-is
        assert received_mobile == mobile


def test_mobile_login_empty_response(mocked_requests):
    """Test mobile login with empty or malformed response."""
    account = DysonAccountCN()
    mobile = "+8613588888888"
    
    # Mock provision API
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def mobile_request_empty_handler(**kwargs):
        return (200, {})  # Missing challengeId
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_REQUEST, mobile_request_empty_handler)
    
    with pytest.raises(KeyError):
        account.login_mobile_otp(mobile)


def test_mobile_login_server_error(mocked_requests):
    """Test mobile login with server error."""
    account = DysonAccountCN()
    mobile = "+8613588888888"
    
    # Mock provision API
    def provision_handler(**kwargs):
        return (200, '"5.0.21061"')
    
    def server_error_handler(**kwargs):
        return (500, {"error": "Internal server error"})
    
    mocked_requests.register_handler("GET", API_PATH_PROVISION_APP, provision_handler)
    mocked_requests.register_handler("POST", API_PATH_MOBILE_REQUEST, server_error_handler)
    
    from libdyson.exceptions import DysonServerError
    
    with pytest.raises(DysonServerError):
        account.login_mobile_otp(mobile)
