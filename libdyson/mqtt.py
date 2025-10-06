import hashlib
import time

from base64 import b64encode
from dataclasses import dataclass
from enum import Enum
from ipaddress import IPv4Address, IPv6Address
from re import match

from libdyson.device_types import DeviceType

class Keys(Enum):
    CONTINUOUS_MONITORING = "rhtm"
    FAN_POWER = "fpwr"
    FAN_SPEED = "fnsp"
    FAN_OSCILLATE = "oson"
    OSCILLATION_MIN = 'osal'
    OSCILLATION_MAX = 'osau'
    FAN_DIRECTION = "fdir"
    AUTO_MODE = "auto"
    HEAT_MODE = "hmod"
    HEAT_TARGET = "hmax"
    SLEEP_TIMER = "sltm"
    RESET_FILTER = "rstf"
    TILT_MIN = 'otal'
    TILT_MAX = 'otau'
    TILT_MODE = 'anct'
    HEAT_STATUS = "hsta"
    VOLATILE_ORGANIC_COMPOUNDS = "va10"
    PARTICULATE_MATTER_25 = "p25r"
    PARTICULATE_MATTER_10 = "p10r"
    PARTICULATE_MATTER_25_LEGACY = "pm25"
    PARTICULATE_MATTER_10_LEGACY = "pm10"
    NITROGEN_DIOXIDE = "noxl"
    CARBON_DIOXIDE = "co2r"
    TEMPERATURE = "tact"
    HUMIDITY = "hact"
    HEPA_FILTER_LIFE = "hflr"
    CARBON_FILTER_LIFE = "cflr"
    FORMALDEHYDE = "hchr"


class TopicType(Enum):
    COMMAND = "command"
    STATUS = "status"
    FAULT = "fault"


class Values(Enum):
    ON = "ON"
    OFF = "OFF"
    FORWARD = "ON"
    REVERSE = "OFF"
    AUTO = "AUTO"
    FAN = "FAN"
    RESET = "RSTF"
    BREEZE = "BRZE"
    CUSTOM = "CUST"


def mqtt_time():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def get_credential_from_wifi_password(wifi_password: str) -> str:
    hash_ = hashlib.sha512()
    hash_.update(wifi_password.encode("utf-8"))
    return b64encode(hash_.digest()).decode("utf-8")


# For some devices, the model in WiFi SSID is not the same as the model for MQTT.
# The model on Dyson Cloud always matches the one used for MQTT.
_DEVICE_TYPE_OVERRIDES = {
    "455A": "455",
}


@dataclass
class Device:
    password: str
    username: str
    device_type: str
    address: IPv4Address | IPv6Address | None


    @property
    def topic_root(self) -> str:
        return f"{self.topic_root}/{self.username}"

    @classmethod
    def from_wifi_info(cls, wifi_ssid: str, wifi_password: str):
        vac_360_eye_result = match(r"^(360EYE-)?(?P<serial>[0-9A-Z]{3}-[A-Z]{2}-[0-9A-Z]{8,})$", wifi_ssid)
        default_result = match(r"^DYSON-([0-9A-Z]{3}-[A-Z]{2}-[0-9A-Z]{8,})-([0-9]{3}[A-Z]?)$", wifi_ssid)
        if vac_360_eye_result is not None:
            serial = vac_360_eye_result.group("serial")
            device_type = DeviceType.VAC_360_EYE
        elif default_result is not None:
            serial = default_result.group(1)
            device_type = default_result.group(2)
            if device_type in _DEVICE_TYPE_OVERRIDES:
                device_type = _DEVICE_TYPE_OVERRIDES[device_type]
        else:
            raise DysonFailedToParseWifiInfo

        credential = get_credential_from_wifi_password(wifi_password)
        return cls(username=serial, password=credential, device_type=device_type, address=None)
