"""Tests for cloud utilities."""

import json
import base64
from unittest.mock import patch, MagicMock

import pytest

from libdyson.cloud.utils import decrypt_password, _unpad


def test_unpad():
    """Test string unpadding."""
    # Test normal case
    padded = "hello\x05\x05\x05\x05\x05"
    assert _unpad(padded) == "hello"
    
    # Test single character padding
    padded = "test\x01"
    assert _unpad(padded) == "test"
    
    # Test larger padding
    padded = "message\x08\x08\x08\x08\x08\x08\x08\x08"
    assert _unpad(padded) == "message"


def test_unpad_edge_cases():
    """Test edge cases in string unpadding."""
    # Test empty string
    assert _unpad("\x01") == ""
    
    # Test string where last character is not padding
    # This tests the actual PKCS#7 padding behavior
    padded = "hello\x03\x03\x03"
    assert _unpad(padded) == "hello"


def test_decrypt_password():
    """Test password decryption."""
    # Create a mock encrypted password
    password_data = {"apPasswordHash": "decrypted_password"}
    password_json = json.dumps(password_data)
    
    # Add PKCS#7 padding
    padding_length = 16 - (len(password_json) % 16)
    padded_json = password_json + chr(padding_length) * padding_length
    
    # Mock the encryption/decryption process
    with patch('libdyson.cloud.utils.Cipher') as mock_cipher:
        mock_decryptor = mock_cipher.return_value.decryptor.return_value
        mock_decryptor.update.return_value = padded_json.encode()
        mock_decryptor.finalize.return_value = b''
        
        with patch('libdyson.cloud.utils.base64.b64decode') as mock_b64decode:
            mock_b64decode.return_value = b'encrypted_data'
            
            result = decrypt_password("encrypted_password")
            assert result == "decrypted_password"
            
            # Verify that the correct methods were called
            mock_b64decode.assert_called_once_with("encrypted_password")
            mock_cipher.assert_called_once()
            mock_decryptor.update.assert_called_once_with(b'encrypted_data')
            mock_decryptor.finalize.assert_called_once()


def test_decrypt_password_with_real_structure():
    """Test password decryption with more realistic structure."""
    # More complex password structure
    password_data = {
        "apPasswordHash": "abcd1234567890",
        "timestamp": "2023-01-01T00:00:00Z"
    }
    password_json = json.dumps(password_data)
    
    # Add PKCS#7 padding
    padding_length = 16 - (len(password_json) % 16)
    padded_json = password_json + chr(padding_length) * padding_length
    
    with patch('libdyson.cloud.utils.Cipher') as mock_cipher:
        mock_decryptor = mock_cipher.return_value.decryptor.return_value
        mock_decryptor.update.return_value = padded_json.encode()
        mock_decryptor.finalize.return_value = b''
        
        with patch('libdyson.cloud.utils.base64.b64decode') as mock_b64decode:
            mock_b64decode.return_value = b'encrypted_data'
            
            result = decrypt_password("encrypted_password")
            assert result == "abcd1234567890"


def test_decrypt_password_invalid_json():
    """Test password decryption with invalid JSON."""
    invalid_json = "not_valid_json"
    padding_length = 16 - (len(invalid_json) % 16)
    padded_invalid = invalid_json + chr(padding_length) * padding_length
    
    with patch('libdyson.cloud.utils.Cipher') as mock_cipher:
        mock_decryptor = mock_cipher.return_value.decryptor.return_value
        mock_decryptor.update.return_value = padded_invalid.encode()
        mock_decryptor.finalize.return_value = b''
        
        with patch('libdyson.cloud.utils.base64.b64decode') as mock_b64decode:
            mock_b64decode.return_value = b'encrypted_data'
            
            with pytest.raises(json.JSONDecodeError):
                decrypt_password("encrypted_password")


def test_decrypt_password_missing_hash_field():
    """Test password decryption with missing apPasswordHash field."""
    password_data = {"otherField": "value"}
    password_json = json.dumps(password_data)
    
    padding_length = 16 - (len(password_json) % 16)
    padded_json = password_json + chr(padding_length) * padding_length
    
    with patch('libdyson.cloud.utils.Cipher') as mock_cipher:
        mock_decryptor = mock_cipher.return_value.decryptor.return_value
        mock_decryptor.update.return_value = padded_json.encode()
        mock_decryptor.finalize.return_value = b''
        
        with patch('libdyson.cloud.utils.base64.b64decode') as mock_b64decode:
            mock_b64decode.return_value = b'encrypted_data'
            
            with pytest.raises(KeyError):
                decrypt_password("encrypted_password")


def test_decrypt_password_base64_decode_error():
    """Test password decryption with base64 decode error."""
    with patch('libdyson.cloud.utils.base64.b64decode') as mock_b64decode:
        mock_b64decode.side_effect = Exception("Invalid base64")
        
        with pytest.raises(Exception):
            decrypt_password("invalid_base64")


def test_decrypt_password_decryption_error():
    """Test password decryption with decryption error."""
    with patch('libdyson.cloud.utils.Cipher') as mock_cipher:
        mock_decryptor = mock_cipher.return_value.decryptor.return_value
        mock_decryptor.update.side_effect = Exception("Decryption failed")
        
        with patch('libdyson.cloud.utils.base64.b64decode') as mock_b64decode:
            mock_b64decode.return_value = b'encrypted_data'
            
            with pytest.raises(Exception):
                decrypt_password("encrypted_password")


def test_decrypt_password_empty_input():
    """Test password decryption with empty input."""
    with patch('libdyson.cloud.utils.base64.b64decode') as mock_b64decode:
        mock_b64decode.return_value = b''
        
        with patch('libdyson.cloud.utils.Cipher') as mock_cipher:
            mock_decryptor = mock_cipher.return_value.decryptor.return_value
            mock_decryptor.update.return_value = b''
            mock_decryptor.finalize.return_value = b''
            
            with pytest.raises((json.JSONDecodeError, UnicodeDecodeError)):
                decrypt_password("")


def test_encryption_constants():
    """Test that encryption constants are correctly defined."""
    from libdyson.cloud.utils import DYSON_ENCRYPTION_KEY, DYSON_ENCRYPTION_INIT_VECTOR
    
    # Test key length (should be 32 bytes for AES-256)
    assert len(DYSON_ENCRYPTION_KEY) == 32
    
    # Test IV length (should be 16 bytes for AES)
    assert len(DYSON_ENCRYPTION_INIT_VECTOR) == 16
    
    # Test that IV is all zeros (as expected)
    assert DYSON_ENCRYPTION_INIT_VECTOR == b'\x00' * 16


def test_cipher_initialization():
    """Test that cipher is initialized correctly."""
    from libdyson.cloud.utils import DYSON_ENCRYPTION_KEY, DYSON_ENCRYPTION_INIT_VECTOR
    
    with patch('libdyson.cloud.utils.Cipher') as mock_cipher_class:
        with patch('libdyson.cloud.utils.algorithms.AES') as mock_aes:
            with patch('libdyson.cloud.utils.modes.CBC') as mock_cbc:
                with patch('libdyson.cloud.utils.base64.b64decode'):
                    mock_cipher_instance = MagicMock()
                    mock_cipher_class.return_value = mock_cipher_instance
                    
                    mock_decryptor = MagicMock()
                    mock_cipher_instance.decryptor.return_value = mock_decryptor
                    
                    # Set up return values
                    mock_decryptor.update.return_value = b'{"apPasswordHash": "test"}\x02\x02'
                    mock_decryptor.finalize.return_value = b''
                    
                    try:
                        decrypt_password("test")
                    except:
                        pass  # We just want to test the initialization
                    
                    # Verify correct initialization
                    mock_aes.assert_called_once_with(DYSON_ENCRYPTION_KEY)
                    mock_cbc.assert_called_once_with(DYSON_ENCRYPTION_INIT_VECTOR)
                    mock_cipher_class.assert_called_once()


def test_unpad_various_padding_sizes():
    """Test unpadding with various padding sizes."""
    # Test all possible padding sizes (1-16 for AES block size)
    for i in range(1, 17):
        message = "A" * (16 - i)  # Message that results in i bytes of padding
        padded = message + chr(i) * i
        assert _unpad(padded) == message
    
    # Test with longer message
    message = "This is a longer message for testing"
    padding_needed = 16 - (len(message) % 16)
    padded = message + chr(padding_needed) * padding_needed
    assert _unpad(padded) == message


def test_unpad_single_character():
    """Test unpadding with single character strings."""
    # Test with single character that has valid padding
    result = _unpad("A")  # ord('A') = 65, so should remove 65 characters (more than string length)
    assert result == ""  # Should return empty string when trying to remove more than length
    
    # Test with padding character at the end
    padded = "test" + chr(4) * 4  # 4 padding characters
    result = _unpad(padded)
    assert result == "test"


def test_unpad_all_padding():
    """Test unpadding when entire string is padding."""
    # String that's all padding characters
    all_padding = chr(3) * 3  # 3 characters, each with value 3
    result = _unpad(all_padding)
    assert result == ""


def test_decrypt_password_minimal_valid():
    """Test decryption with minimal valid input."""
    # Create a minimal valid encrypted password
    import base64
    import json
    from libdyson.cloud.utils import DYSON_ENCRYPTION_KEY, DYSON_ENCRYPTION_INIT_VECTOR
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    
    # Create test data
    test_data = {"apPasswordHash": "test_password"}
    test_json = json.dumps(test_data)
    
    # Add padding
    padding_length = 16 - (len(test_json) % 16)
    padded_data = test_json + chr(padding_length) * padding_length
    
    # Encrypt with the known key and IV
    cipher = Cipher(algorithms.AES(DYSON_ENCRYPTION_KEY), modes.CBC(DYSON_ENCRYPTION_INIT_VECTOR))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data.encode()) + encryptor.finalize()
    
    # Base64 encode
    encrypted_b64 = base64.b64encode(encrypted).decode()
    
    # Test decryption
    result = decrypt_password(encrypted_b64)
    assert result == "test_password"


def test_decrypt_password_unicode_content():
    """Test decryption with unicode content."""
    # Create test data with unicode
    import base64
    import json
    from libdyson.cloud.utils import DYSON_ENCRYPTION_KEY, DYSON_ENCRYPTION_INIT_VECTOR
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    
    test_data = {"apPasswordHash": "tëst_pässwörd_üñíçødé"}
    test_json = json.dumps(test_data, ensure_ascii=False)
    
    # Add padding
    padding_length = 16 - (len(test_json.encode('utf-8')) % 16)
    padded_data = test_json + chr(padding_length) * padding_length
    
    # Encrypt
    cipher = Cipher(algorithms.AES(DYSON_ENCRYPTION_KEY), modes.CBC(DYSON_ENCRYPTION_INIT_VECTOR))
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data.encode('utf-8')) + encryptor.finalize()
    
    # Base64 encode
    encrypted_b64 = base64.b64encode(encrypted).decode()
    
    # Test decryption
    result = decrypt_password(encrypted_b64)
    assert result == "tëst_pässwörd_üñíçødé"
