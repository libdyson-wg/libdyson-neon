"""Dyson device discovery."""

import socket
import threading
from typing import Callable, Optional

from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf

from .dyson_device import DysonDevice

TYPE_DYSON_360_EYE = "_360eye_mqtt._tcp.local."
TYPE_DYSON_FAN = "_dyson_mqtt._tcp.local."


class DysonDiscovery:
    """Dyson device discovery."""

    def __init__(self):
        """Initialize the instance."""
        self._registered = {}
        self._discovered = {}
        self._lock = threading.Lock()
        self._browser = None

    def register_device(
        self,
        device: DysonDevice,
        callback: Callable[[str, Optional[str]], None],
    ) -> None:
        """Register a device.

        The callback is called with (ip_address, mac_address) when the device
        is discovered. mac_address is None if not advertised in the mDNS record.
        """
        with self._lock:
            if device.serial in self._discovered:
                address, mac = self._discovered[device.serial]
                callback(address, mac)
            else:
                self._registered[device.serial] = callback

    def device_discovered(self, info: ServiceInfo) -> None:
        """Call when a device is discovered."""
        if info.type == TYPE_DYSON_360_EYE:
            serial = (info.name.split(".")[0]).split("-", 1)[1]
        else:  # TYPE_DYSON_FAN
            serial = (info.name.split(".")[0]).split("_")[1]
        address = socket.inet_ntoa(info.addresses[0])
        mac = self._extract_mac(info)
        with self._lock:
            if serial in self._registered:
                callback = self._registered.pop(serial)
                callback(address, mac)
            else:
                # maps serial -> (ip_address, mac_address_or_None)
                self._discovered[serial] = (address, mac)

    def _extract_mac(self, info: ServiceInfo) -> Optional[str]:
        """Extract MAC address from a mDNS ServiceInfo record.

        Tries two sources in order:

        Strategy 1 — TXT record properties (bytes keys). Some firmware versions
        advertise the MAC here; the key name varies by model generation.
        """
        properties = getattr(info, "properties", {}) or {}
        for key in (b"mac", b"MAC", b"macAddress", b"mac_address"):
            val = properties.get(key)
            if val is not None:
                return val.decode("utf-8")

        # Strategy 2 — mDNS server hostname, e.g. "Dyson-AABBCCDDEEFF.local."
        # The MAC appears as a 12-hex-char segment with no separators.
        # Not all firmware versions use this hostname format, so may return None.
        server = getattr(info, "server", None)
        if server:
            hostname = server.rstrip(".")
            for segment in hostname.split("-"):
                if len(segment) == 12 and all(
                    c in "0123456789abcdefABCDEF" for c in segment
                ):
                    return segment

        return None  # MAC not advertised in this mDNS record

    def start_discovery(self, zeroconf_instance: Optional[Zeroconf] = None) -> None:
        """Start discovery."""
        listener = DysonListener(self)
        zeroconf = zeroconf_instance or Zeroconf()
        self._browser = ServiceBrowser(
            zeroconf,
            [TYPE_DYSON_360_EYE, TYPE_DYSON_FAN],
            listener,
        )

    def stop_discovery(self) -> None:
        """Stop discovery."""
        if self._browser is None:
            return
            
        try:
            # Cancel the browser first
            self._browser.cancel()
        except RuntimeError:
            # Throws when called from callback
            # cannot join current thread
            pass
        except Exception as e:
            # Log any other exceptions but don't fail
            print(f"Error cancelling discovery browser: {e}")
        
        try:
            # Close zeroconf instance
            if hasattr(self._browser, 'zc') and self._browser.zc:
                self._browser.zc.close()
        except Exception as e:
            print(f"Error closing zeroconf: {e}")
        
        # Clear references
        self._browser = None
        
        # Clear discovery state
        with self._lock:
            self._registered.clear()
            self._discovered.clear()


class DysonListener:
    """Listener for zeroconf events."""

    def __init__(self, dyson_discovery: DysonDiscovery):
        """Initialize the listener."""
        self._dyson_discovery = dyson_discovery

    def add_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
        """Add a new service."""
        info = zeroconf.get_service_info(type, name)
        self._dyson_discovery.device_discovered(info)

    def update_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
        """Update a service."""
        # Currently not doing anything

    def remove_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
        """Remove a service."""
        # Currently not doing anything
