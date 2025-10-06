import json
from enum import Enum
from typing import Callable, Any
from ipaddress import IPv4Address, IPv6Address
from dataclasses import dataclass
from paho.mqtt.client import Client, MQTTv31, ConnackCode, MQTTMessage
from threading import Event
from logging import getLogger

import libdyson.mqtt as mqtt
import libdyson.iot as iot
from libdyson.exceptions import DysonUnknownMQTTReturnCode, DysonInvalidCredential

SENSOR_OFF = -1
SENSOR_INIT = -2
SENSOR_FAIL = -3

CONNECT_TIMEOUT = 10

logger = getLogger(__name__)


class Feature(Enum):
    """List of features, keyed to the corresponding MQTT Key to use to determine if the feature is supported."""
    CONTINUOUS_MONITORING = mqtt.Keys.CONTINUOUS_MONITORING
    AUTO_MODE = mqtt.Keys.AUTO_MODE
    FAN_POWER = mqtt.Keys.FAN_POWER
    FAN_SPEED = mqtt.Keys.FAN_SPEED
    FAN_OSCILLATE = mqtt.Keys.FAN_OSCILLATE
    FAN_DIRECTION = mqtt.Keys.FAN_DIRECTION
    HEAT = mqtt.Keys.HEAT_MODE
    SLEEP_TIMER = mqtt.Keys.SLEEP_TIMER
    RESET_FILTER = mqtt.Keys.HEPA_FILTER_LIFE
    HEPA_FILTER_SENSOR = mqtt.Keys.HEPA_FILTER_LIFE
    TILT = mqtt.Keys.TILT_MIN

    SENSOR_VOC = mqtt.Keys.VOLATILE_ORGANIC_COMPOUNDS
    SENSOR_PM25 = mqtt.Keys.PARTICULATE_MATTER_25
    SENSOR_PM25_LEGACY = mqtt.Keys.PARTICULATE_MATTER_25_LEGACY
    SENSOR_PM10 = mqtt.Keys.PARTICULATE_MATTER_10
    SENSOR_PM10_LEGACY = mqtt.Keys.PARTICULATE_MATTER_10_LEGACY
    SENSOR_NO2 = mqtt.Keys.NITROGEN_DIOXIDE
    SENSOR_CO2 = mqtt.Keys.CARBON_DIOXIDE
    SENSOR_TEMPERATURE = mqtt.Keys.TEMPERATURE
    SENSOR_HUMIDITY = mqtt.Keys.HUMIDITY
    SENSOR_FORMALDEHYDE = mqtt.Keys.FORMALDEHYDE
    SENSOR_HEPA_FILTER_LIFE = mqtt.Keys.HEPA_FILTER_LIFE
    SENSOR_CARBON_FILTER_LIFE = mqtt.Keys.CARBON_FILTER_LIFE


def sensor_value(value: str, divisor: int = 1) -> float:
    match value.upper():
        case "OFF":
            return SENSOR_OFF
        case "INIT":
            return SENSOR_INIT
        case "FAIL":
            return SENSOR_FAIL
        case "NONE":
            return SENSOR_FAIL

    if divisor == 1:
        return float(value)

    return float(value) / divisor


class Category(Enum):
    EC = "ec"
    FLRC = "flrc"
    HC = "hc"
    LIGHT = "light"
    ROBOT = "robot"
    WEARABLE = "wearable"


@dataclass
class DeviceProps:
    mqtt: mqtt.Device | None
    iot: iot.Device | None
    serial: str
    name: str
    wifi_ssid: str | None
    wifi_password: str | None
    model: str
    type: str | None
    features: list[Feature] | None
    category: Category | None


class ConnectedDevice(DeviceProps):
    props: DeviceProps
    _client: Client | None = None
    _connected: Event = Event()
    _connect_error: Any | None = None

    _status: dict | None = None

    def __init__(self, props: DeviceProps):
        if props.local_ip is None:
            props.local_ip = self.resolve_local_ip()

        if props.features is None:
            props.features = self.interview()

        if props.wifi_password is not None and props.wifi_ssid is not None:
            props.mqtt = mqtt.Device.from_wifi_info(props.wifi_ssid, props.wifi_password)

        self.props = props
        self._init_client()

    def _init_client(self):
        if self._client is not None:
            return

        self._client = Client(protocol=MQTTv31)
        self._client.username_pw_set(
            self.props.mqtt.username, self.props.mqtt.password
        )

        self._client.on_connect = self.on_connect
        self._client.on_disconnect = self.on_disconnect
        self._client.connect_async(str(self.props.mqtt.address))

    def _connect(self):
        if self._client is None:
            raise RuntimeError("Client not initialized")

        if self._connected.is_set():
            return

        self._client.loop_start()

        if not self._connected.wait(timeout=CONNECT_TIMEOUT):
            if self._connect_error is not None:
                logger.error("MQTT connection failed, disconnecting")
                raise self._connect_error
            else:
                logger.error("MQTT connection timed out after %d seconds", CONNECT_TIMEOUT)
                raise TimeoutError("MQTT connection timed out after %d seconds" % CONNECT_TIMEOUT)

        logger.debug("Connected to device %s", self.props.serial)

    def _on_message(self, client: Client, userdata: None, msg: MQTTMessage):
        payload: dict = json.loads(msg.payload)

        match msg.topic:
            case self.get_topic(mqtt.TopicType.STATUS):
            case self.get_topic(mqtt.TopicType.FAULT):


    def _handle_state(self, payload: dict):
        match payload["msg"]:
            case "CURRENT-STATE", "STATE-CHANGE":
                logger.debug("New state: %s", payload)
                self._update_status(payload)
                if not self._status_data_available.is_set():
                    self._status_data_available.set()
                for callback in self._callbacks:
                    callback(MessageType.STATE)

        payload = json.loads(msg.payload.decode("utf-8"))
        self._handle_message(payload)

    def on_connect(self, client: Client, userdata: Any, flags: None, rc: int):
        logger.debug("MQTT connection attempt result code: %d", rc)

        match rc:
            case ConnackCode.CONNACK_ACCEPTED:
                logger.debug("MQTT Connection accepted")
            case ConnackCode.CONNACK_REFUSED_BAD_USERNAME_PASSWORD:
                logger.error("MQTT connection refused: Bad username/password (rc=1)")
                self._connect_error = DysonInvalidCredential
            case 7:
                logger.error("MQTT connection refused: Connection refused (rc=7)")
                self._connect_error = DysonUnknownMQTTReturnCode

        self._connected.set()

    def on_disconnect(self, client: Client, userdata: None, rc: int):
        logger.debug("MQTT disconnected with result code %d", rc)
        self._connected.clear()

    def get_topic(self, topic_type: mqtt.TopicType) -> str:
        match topic_type:
            case mqtt.TopicType.STATUS:
                return f"{self.props.mqtt.topic_root}/status/current"
            case mqtt.TopicType.COMMAND:
                return f"{self.props.mqtt.topic_root}/command"
            case mqtt.TopicType.FAULT:
                return f"{self.props.mqtt.topic_root}/status/fault"

    def resolve_local_ip(self) -> IPv4Address | IPv6Address | None:
        ...

    def subscribe_raw(self, handler: Callable[[str], None]):
        ...

    def publish_raw(self, topic: str, payload: str):
        ...

    def interview(self) -> list[Feature]:
        ...
