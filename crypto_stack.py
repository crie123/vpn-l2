"""
Crypto stack module using teeth-gnashing library for VPN encryption.

This module provides encryption/decryption functionality using the teeth-gnashing
production-grade library, which implements dynamic snapshot-based encryption with
server-client architecture.
"""

import os
import json
import base64
from typing import Optional, Union, TYPE_CHECKING

# Import teeth-gnashing client components - only import what we need
try:
    from teeth_gnashing.client import CryptoClient, CryptoConfig, CryptoError, AuthenticationError, SnapshotError
except ImportError as e:
    # Handle broken imports in teeth-gnashing package
    print(f"Warning: Error importing from teeth_gnashing.client: {e}")
    print("Attempting alternative import strategy...")
    
    # Try importing just the client module directly
    import sys
    import importlib.util
    spec = importlib.util.find_spec("teeth_gnashing.client")
    if TYPE_CHECKING or spec is not None:
        from teeth_gnashing.client import CryptoClient, CryptoConfig, CryptoError, AuthenticationError, SnapshotError

# Global client instance
_crypto_client: Optional[CryptoClient] = None


def load_config(config_path: str = "client_config.json") -> dict:
    """Load client configuration from JSON file."""
    if not os.path.exists(config_path):
        raise RuntimeError(f"Secret key config not found: {config_path}")
    
    with open(config_path, "r") as f:
        return json.load(f)


def get_crypto_client(server_url: str, config_path: str = "client_config.json") -> CryptoClient:
    """
    Get or initialize the global crypto client instance.
    
    Args:
        server_url: Base URL of the crypto server (e.g., http://localhost:8000)
        config_path: Path to client configuration JSON file
        
    Returns:
        Initialized CryptoClient instance
        
    Raises:
        RuntimeError: If configuration file not found
        CryptoError: If initialization fails
    """
    global _crypto_client
    
    if _crypto_client is None:
        config_data = load_config(config_path)
        
        # Create CryptoConfig from loaded data
        crypto_config = CryptoConfig(
            server_url=server_url,
            secret_key=base64.b64decode(config_data["secret_key"]),
            max_drift=config_data.get("max_drift", 60),
            handshake_points=config_data.get("handshake_points", 8),
            hash_size=config_data.get("hash_size", 32),
            array_size=config_data.get("array_size", 256)
        )
        
        _crypto_client = CryptoClient(crypto_config)
    
    return _crypto_client


async def authenticate_with_server(server_url: str, config_path: str = "client_config.json") -> None:
    """
    Perform authentication handshake with the crypto server.
    
    Args:
        server_url: Base URL of the crypto server
        config_path: Path to client configuration JSON file
        
    Raises:
        AuthenticationError: If handshake fails
    """
    client = get_crypto_client(server_url, config_path)
    await client.authenticate()


async def encrypt_message(message: Union[str, bytes], server_url: str, 
                         config_path: str = "client_config.json") -> bytes:
    """
    Encrypt a message using teeth-gnashing.
    
    This function uses dynamic snapshot-based encryption with server-generated
    snapshots and local key derivation.
    
    Args:
        message: String or bytes to encrypt
        server_url: Base URL of the crypto server
        config_path: Path to client configuration JSON file
        
    Returns:
        Encrypted message as bytes (format: hash + salt + encrypted_data)
        
    Raises:
        AuthenticationError: If authentication with server fails
        SnapshotError: If snapshot retrieval/verification fails
        CryptoError: If encryption fails
    """
    client = get_crypto_client(server_url, config_path)
    return await client.encrypt_message(message)


async def decrypt_message(encrypted: bytes, server_url: str,
                         config_path: str = "client_config.json") -> bytes:
    """
    Decrypt a message using teeth-gnashing.
    
    This function reverses the encryption using the same snapshot-based approach.
    
    Args:
        encrypted: Encrypted message bytes
        server_url: Base URL of the crypto server
        config_path: Path to client configuration JSON file
        
    Returns:
        Decrypted message as bytes
        
    Raises:
        AuthenticationError: If authentication with server fails
        SnapshotError: If snapshot retrieval/verification fails
        CryptoError: If decryption fails or integrity check fails
    """
    client = get_crypto_client(server_url, config_path)
    return await client.decrypt_message(encrypted)


async def close_crypto_client() -> None:
    """Close the global crypto client session."""
    global _crypto_client
    if _crypto_client is not None:
        await _crypto_client.close()
        _crypto_client = None
