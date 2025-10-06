from dataclasses import dataclass

@dataclass
class Device:
    endpoint: str
    client_id: str
    custom_authorizer_name: str
    token_key: str
    token_signature: str
    token_value: str
