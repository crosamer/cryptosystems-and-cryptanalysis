from abc import ABC, abstractmethod
import string

class BaseCipher(ABC):
    """Base class for all cipher implementations"""
    
    def __init__(self):
        self.alphabet = string.ascii_uppercase
        self.alphabet_size = 26
    
    @abstractmethod
    def encrypt(self, plaintext: str, key: str) -> str:
        """Encrypt plaintext using the given key"""
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext: str, key: str) -> str:
        """Decrypt ciphertext using the given key"""
        pass
    
    def encrypt_bytes(self, data: bytes, key: str) -> bytes:
        """Encrypt binary data - default implementation"""
        # Convert bytes to string representation and encrypt
        text = ''.join(chr(b) for b in data)
        encrypted_text = self.encrypt(text, key)
        return encrypted_text.encode('utf-8', errors='ignore')
    
    def clean_text(self, text: str, keep_spaces: bool = False) -> str:
        """Clean text to contain only alphabetic characters"""
        if keep_spaces:
            return ''.join(c.upper() if c.isalpha() else (' ' if c.isspace() else '') for c in text)
        return ''.join(c.upper() for c in text if c.isalpha())
    
    def format_output(self, text: str, group_size: int = 5) -> dict:
        """Format output text in different ways"""
        return {
            'no_spaces': text.replace(' ', ''),
            'grouped': ' '.join(text[i:i+group_size] for i in range(0, len(text), group_size))
        }
    
    def mod_inverse(self, a: int, m: int) -> int:
        """Calculate modular multiplicative inverse"""
        def extended_gcd(a, b):
            if a == 0:
                return b, 0, 1
            gcd, x1, y1 = extended_gcd(b % a, a)
            x = y1 - (b // a) * x1
            y = x1
            return gcd, x, y
        
        gcd, x, _ = extended_gcd(a % m, m)
        if gcd != 1:
            raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
        return (x % m + m) % m
