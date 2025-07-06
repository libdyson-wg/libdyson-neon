"""Tests for 360 Eye cloud client."""

from datetime import datetime, timedelta
from typing import Optional, Tuple
from unittest.mock import patch

import pytest
from requests.auth import AuthBase

from libdyson.cloud import DysonAccount
from libdyson.cloud.cloud_360_eye import CleaningType, DysonCloud360Eye, CleaningTask

from . import AUTH_INFO
from .mocked_requests import MockedRequests

SERIAL = "JH1-US-HBB1111A"


def test_cleaning_task_from_raw():
    """Test CleaningTask creation from raw data."""
    raw_data = {
        "Clean": "cleaning-123",
        "Started": "2021-02-09T12:10:07",
        "Finished": "2021-02-09T14:14:11",
        "Area": 34.70,
        "Charges": 1,
        "Type": "Scheduled",
        "IsInterim": True,
    }

    task = CleaningTask.from_raw(raw_data)

    assert task.cleaning_id == "cleaning-123"
    assert task.area == 34.70
    assert task.charges == 1
    assert task.cleaning_type == CleaningType.Scheduled
    assert task.is_interim is True
    assert isinstance(task.start_time, datetime)
    assert isinstance(task.finish_time, datetime)
    assert task.cleaning_time.total_seconds() > 0


def test_cleaning_task_cleaning_time():
    """Test cleaning time calculation."""
    raw_data = {
        "Clean": "cleaning-123",
        "Started": "2021-02-09T12:00:00",
        "Finished": "2021-02-09T14:30:00",
        "Area": 34.70,
        "Charges": 1,
        "Type": "Immediate",
        "IsInterim": False,
    }

    task = CleaningTask.from_raw(raw_data)

    # Should be 2.5 hours
    expected_duration = timedelta(hours=2, minutes=30)
    assert task.cleaning_time == expected_duration


def test_cleaning_task_all_types():
    """Test CleaningTask with all cleaning types."""
    types_to_test = ["Immediate", "Manual", "Scheduled"]

    for cleaning_type in types_to_test:
        raw_data = {
            "Clean": f"cleaning-{cleaning_type}",
            "Started": "2021-02-09T12:10:07",
            "Finished": "2021-02-09T14:14:11",
            "Area": 34.70,
            "Charges": 1,
            "Type": cleaning_type,
            "IsInterim": False,
        }

        task = CleaningTask.from_raw(raw_data)
        assert task.cleaning_type == CleaningType(cleaning_type)


def test_cleaning_task_invalid_type():
    """Test CleaningTask with invalid type."""
    raw_data = {
        "Clean": "cleaning-123",
        "Started": "2021-02-09T12:10:07",
        "Finished": "2021-02-09T14:14:11",
        "Area": 34.70,
        "Charges": 1,
        "Type": "InvalidType",
        "IsInterim": True,
    }

    with pytest.raises(ValueError):
        CleaningTask.from_raw(raw_data)


def test_cleaning_task_invalid_datetime():
    """Test CleaningTask with invalid datetime format."""
    raw_data = {
        "Clean": "cleaning-123",
        "Started": "invalid-datetime",
        "Finished": "2021-02-09T14:14:11",
        "Area": 34.70,
        "Charges": 1,
        "Type": "Scheduled",
        "IsInterim": True,
    }

    with pytest.raises(ValueError):
        CleaningTask.from_raw(raw_data)


def test_cleaning_task_zero_charges():
    """Test CleaningTask with zero charges."""
    raw_data = {
        "Clean": "cleaning-123",
        "Started": "2021-02-09T12:10:07",
        "Finished": "2021-02-09T14:14:11",
        "Area": 34.70,
        "Charges": 0,
        "Type": "Manual",
        "IsInterim": False,
    }

    task = CleaningTask.from_raw(raw_data)
    assert task.charges == 0


def test_cleaning_task_large_area():
    """Test CleaningTask with large area value."""
    raw_data = {
        "Clean": "cleaning-123",
        "Started": "2021-02-09T12:10:07",
        "Finished": "2021-02-09T14:14:11",
        "Area": 999.99,
        "Charges": 3,
        "Type": "Immediate",
        "IsInterim": True,
    }

    task = CleaningTask.from_raw(raw_data)
    assert task.area == 999.99


def test_cleaning_task_frozen():
    """Test that CleaningTask is immutable."""
    raw_data = {
        "Clean": "cleaning-123",
        "Started": "2021-02-09T12:10:07",
        "Finished": "2021-02-09T14:14:11",
        "Area": 34.70,
        "Charges": 1,
        "Type": "Scheduled",
        "IsInterim": True,
    }

    task = CleaningTask.from_raw(raw_data)

    # Should not be able to modify fields (frozen=True)
    with pytest.raises(AttributeError):
        task.cleaning_id = "new-id"


def test_get_cleaning_history(mocked_requests: MockedRequests):
    """Test get cleaning history from the cloud."""
    cleaning1_id = "edcda2c9-5088-455e-b2ee-9422ef70afb2"
    cleaning2_id = "98cf2de1-190f-4e68-97b5-c57e7e0604d0"
    clean_history = {
        "TriviaMessage": "Your robot has cleaned 1000yds²",
        "TriviaArea": 800.1243,
        "Entries": [
            {
                "Clean": cleaning1_id,
                "Started": "2021-02-10T17:02:00",
                "Finished": "2021-02-10T17:02:10",
                "Area": 0.00,
                "Charges": 0,
                "Type": "Immediate",
                "IsInterim": False,
            },
            {
                "Clean": cleaning2_id,
                "Started": "2021-02-09T12:10:07",
                "Finished": "2021-02-09T14:14:11",
                "Area": 34.70,
                "Charges": 1,
                "Type": "Scheduled",
                "IsInterim": True,
            },
        ],
    }

    def _clean_history_handler(
        auth: Optional[AuthBase], **kwargs
    ) -> Tuple[int, Optional[dict]]:
        assert auth is not None
        return (0, clean_history)

    mocked_requests.register_handler(
        "GET", f"/v1/assets/devices/{SERIAL}/cleanhistory", _clean_history_handler
    )

    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)
    cleaning_tasks = device.get_cleaning_history()
    assert len(cleaning_tasks) == 2
    task = cleaning_tasks[0]
    assert task.cleaning_id == cleaning1_id
    assert task.start_time == datetime(2021, 2, 10, 17, 2, 0)
    assert task.finish_time == datetime(2021, 2, 10, 17, 2, 10)
    assert task.cleaning_time == timedelta(seconds=10)
    assert task.area == 0.0
    assert task.charges == 0
    assert task.cleaning_type == CleaningType.Immediate
    assert task.is_interim is False
    task = cleaning_tasks[1]
    assert task.cleaning_id == cleaning2_id
    assert task.start_time == datetime(2021, 2, 9, 12, 10, 7)
    assert task.finish_time == datetime(2021, 2, 9, 14, 14, 11)
    assert task.cleaning_time == timedelta(hours=2, minutes=4, seconds=4)
    assert task.area == 34.7
    assert task.charges == 1
    assert task.cleaning_type == CleaningType.Scheduled
    assert task.is_interim is True


def test_get_cleaning_map(mocked_requests: MockedRequests):
    """Test get cleaning map from the cloud."""
    cleaning_id = "edcda2c9-5088-455e-b2ee-9422ef70afb2"
    cleaning_map = b"mocked_png_image"

    def _clean_history_handler(auth: Optional[AuthBase], **kwargs) -> Tuple[int, bytes]:
        assert auth is not None
        return (0, cleaning_map)

    mocked_requests.register_handler(
        "GET",
        f"/v1/mapvisualizer/devices/{SERIAL}/map/{cleaning_id}",
        _clean_history_handler,
    )

    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)
    assert device.get_cleaning_map(cleaning_id) == cleaning_map

    # Non existed map
    assert device.get_cleaning_map("another_id") is None


def test_get_cleaning_history_error_handling(mocked_requests):
    """Test error handling in cleaning history retrieval."""
    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)

    def error_handler(**kwargs):
        return (500, {"error": "Server error"})

    mocked_requests.register_handler(
        "GET", f"/v1/assets/devices/{SERIAL}/cleanhistory", error_handler
    )

    from libdyson.exceptions import DysonServerError

    with pytest.raises(DysonServerError):
        device.get_cleaning_history()


def test_get_cleaning_history_empty_response(mocked_requests):
    """Test cleaning history retrieval with empty response."""
    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)

    def empty_handler(**kwargs):
        return (200, {"Entries": []})

    mocked_requests.register_handler(
        "GET", f"/v1/assets/devices/{SERIAL}/cleanhistory", empty_handler
    )

    tasks = device.get_cleaning_history()
    assert len(tasks) == 0


def test_get_cleaning_history_malformed_response(mocked_requests):
    """Test cleaning history retrieval with malformed response."""
    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)

    def malformed_handler(**kwargs):
        return (200, {"WrongKey": []})

    mocked_requests.register_handler(
        "GET", f"/v1/assets/devices/{SERIAL}/cleanhistory", malformed_handler
    )

    with pytest.raises(KeyError):
        device.get_cleaning_history()


def test_get_cleaning_history_auth_required(mocked_requests):
    """Test that cleaning history requires authentication."""
    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)

    auth_received = None

    def auth_check_handler(auth=None, **kwargs):
        nonlocal auth_received
        auth_received = auth
        return (200, {"Entries": []})

    mocked_requests.register_handler(
        "GET", f"/v1/assets/devices/{SERIAL}/cleanhistory", auth_check_handler
    )

    device.get_cleaning_history()

    # Should have received authentication
    assert auth_received is not None


def test_get_cleaning_map_not_found(mocked_requests):
    """Test cleaning map retrieval when map doesn't exist."""
    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)
    cleaning_id = "non-existent-id"

    def not_found_handler(**kwargs):
        return (404, None)

    mocked_requests.register_handler(
        "GET", f"/v1/mapvisualizer/devices/{SERIAL}/map/{cleaning_id}", not_found_handler
    )

    result = device.get_cleaning_map(cleaning_id)
    assert result is None


def test_get_cleaning_map_success(mocked_requests):
    """Test successful cleaning map retrieval."""
    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)
    cleaning_id = "valid-cleaning-id"
    expected_content = b"PNG_IMAGE_DATA"

    def success_handler(**kwargs):
        return (200, expected_content)

    mocked_requests.register_handler(
        "GET", f"/v1/mapvisualizer/devices/{SERIAL}/map/{cleaning_id}", success_handler
    )

    result = device.get_cleaning_map(cleaning_id)
    assert result == expected_content


def test_get_cleaning_map_server_error(mocked_requests):
    """Test cleaning map retrieval with server error."""
    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)
    cleaning_id = "test-id"

    def server_error_handler(**kwargs):
        return (500, {"error": "Server error"})

    mocked_requests.register_handler(
        "GET", f"/v1/mapvisualizer/devices/{SERIAL}/map/{cleaning_id}", server_error_handler
    )

    from libdyson.exceptions import DysonServerError

    with pytest.raises(DysonServerError):
        device.get_cleaning_map(cleaning_id)


def test_get_cleaning_map_auth_required(mocked_requests):
    """Test that cleaning map requires authentication."""
    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)
    cleaning_id = "test-id"

    auth_received = None

    def auth_check_handler(auth=None, **kwargs):
        nonlocal auth_received
        auth_received = auth
        return (200, b"map_data")

    mocked_requests.register_handler(
        "GET", f"/v1/mapvisualizer/devices/{SERIAL}/map/{cleaning_id}", auth_check_handler
    )

    device.get_cleaning_map(cleaning_id)

    # Should have received authentication
    assert auth_received is not None


def test_dyson_cloud_360_eye_inheritance():
    """Test that DysonCloud360Eye inherits from DysonCloudDevice."""
    from libdyson.cloud.cloud_device import DysonCloudDevice

    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)

    assert isinstance(device, DysonCloudDevice)


def test_dyson_cloud_360_eye_serial_access():
    """Test that serial number is accessible."""
    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)

    # Should be able to access serial through the base class
    assert device._serial == SERIAL


def test_cleaning_type_enum_values():
    """Test CleaningType enum values."""
    assert CleaningType.Immediate.value == "Immediate"
    assert CleaningType.Manual.value == "Manual"
    assert CleaningType.Scheduled.value == "Scheduled"


def test_cleaning_type_enum_iteration():
    """Test that all CleaningType values are accessible."""
    all_types = list(CleaningType)
    assert len(all_types) == 3
    assert CleaningType.Immediate in all_types
    assert CleaningType.Manual in all_types
    assert CleaningType.Scheduled in all_types


def test_get_cleaning_history_multiple_tasks(mocked_requests):
    """Test cleaning history with multiple tasks."""
    account = DysonAccount(AUTH_INFO)
    device = DysonCloud360Eye(account, SERIAL)

    def multi_task_handler(**kwargs):
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
                },
                {
                    "Clean": "cleaning-2",
                    "Started": "2021-02-10T14:00:00",
                    "Finished": "2021-02-10T15:30:00",
                    "Area": 30.5,
                    "Charges": 2,
                    "Type": "Scheduled",
                    "IsInterim": True,
                }
            ]
        })

    mocked_requests.register_handler(
        "GET", f"/v1/assets/devices/{SERIAL}/cleanhistory", multi_task_handler
    )

    tasks = device.get_cleaning_history()

    assert len(tasks) == 2
    assert tasks[0].cleaning_id == "cleaning-1"
    assert tasks[0].cleaning_type == CleaningType.Immediate
    assert tasks[1].cleaning_id == "cleaning-2"
    assert tasks[1].cleaning_type == CleaningType.Scheduled
