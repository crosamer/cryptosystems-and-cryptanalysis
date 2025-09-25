from .base_cipher import BaseCipher
import random
import os

class OneTimePadCipher(BaseCipher):
    """Implementation of One-Time Pad Cipher"""
    
    def __init__(self):
        super().__init__()
        self.key_file_path = "keys"
        os.makedirs(self.key_file_path, exist_ok=True)
    
    def generate_key_file(self, length=10000, filename="otp_key.txt"):
        """Generate a random key file for One-Time Pad"""
        key = ''.join(random.choice(self.alphabet) for _ in range(length))
        filepath = os.path.join(self.key_file_path, filename)
        
        with open(filepath, 'w') as f:
            f.write(key)
        
        return filepath
    
    def read_key_from_file(self, filepath):
        """Read key from file"""
        try:
            with open(filepath, 'r') as f:
                return f.read().upper()
        except FileNotFoundError:
            raise ValueError(f"Key file not found: {filepath}")
        except Exception as e:
            raise ValueError(f"Error reading key file: {str(e)}")
    
    def _prepare_key(self, key_source: str, text_length: int) -> str:
        """Prepare key from file or direct input"""
        if key_source.startswith('file:'):
            # Key from file
            filepath = key_source[5:]  # Remove 'file:' prefix
            if not os.path.isabs(filepath):
                filepath = os.path.join(self.key_file_path, filepath)
            
            key = self.read_key_from_file(filepath)
        else:
            # Direct key input
            key = self.clean_text(key_source)
        
        if len(key) < text_length:
            raise ValueError(f"Key length ({len(key)}) is shorter than text length ({text_length})")
        
        return key[:text_length]  # Use only the required length
    
    def encrypt(self, plaintext: str, key: str) -> str:
        cleaned_text = self.clean_text(plaintext)
        if not cleaned_text:
            return ""
        
        prepared_key = self._prepare_key(key, len(cleaned_text))
        encrypted = ""
        
        for i, char in enumerate(cleaned_text):
            if char in self.alphabet:
                text_index = self.alphabet.index(char)
                key_index = self.alphabet.index(prepared_key[i])
                encrypted_index = (text_index + key_index) % self.alphabet_size
                encrypted += self.alphabet[encrypted_index]
        
        return encrypted
    
    def decrypt(self, ciphertext: str, key: str) -> str:
        cleaned_text = self.clean_text(ciphertext)
        if not cleaned_text:
            return ""
        
        prepared_key = self._prepare_key(key, len(cleaned_text))
        decrypted = ""
        
        for i, char in enumerate(cleaned_text):
            if char in self.alphabet:
                text_index = self.alphabet.index(char)
                key_index = self.alphabet.index(prepared_key[i])
                decrypted_index = (text_index - key_index) % self.alphabet_size
                decrypted += self.alphabet[decrypted_index]
        
        return decrypted
