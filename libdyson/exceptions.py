"""Dyson Python library exceptions."""


class DysonException(Exception):
    """Base class for exceptions."""

class DysonInvalidCredential(DysonException):
    """Represents invalid mqtt credential."""

class DysonUnknownMQTTReturnCode(DysonException):
    """Represents unknown mqtt return code."""