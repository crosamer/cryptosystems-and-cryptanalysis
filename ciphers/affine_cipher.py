from .base_cipher import BaseCipher
import math

class AffineCipher(BaseCipher):
    """Implementation of Affine Cipher"""
    
    def _parse_key(self, key: str) -> tuple:
        """Parse key string into a and b values"""
        try:
            parts = key.split(',')
            if len(parts) != 2:
                raise ValueError("Affine cipher key must be in format 'a,b'")
            
            a = int(parts[0].strip())
            b = int(parts[1].strip())
            
            if math.gcd(a, self.alphabet_size) != 1:
                raise ValueError(f"'a' value ({a}) must be coprime with {self.alphabet_size}")
            
            return a, b
        except ValueError as e:
            if "invalid literal" in str(e):
                raise ValueError("Affine cipher key must contain two integers separated by comma")
            raise e
    
    def encrypt(self, plaintext: str, key: str) -> str:
        a, b = self._parse_key(key)
        cleaned_text = self.clean_text(plaintext)
        encrypted = ""
        
        for char in cleaned_text:
            if char in self.alphabet:
                x = self.alphabet.index(char)
                encrypted_index = (a * x + b) % self.alphabet_size
                encrypted += self.alphabet[encrypted_index]
        
        return encrypted
    
    def decrypt(self, ciphertext: str, key: str) -> str:
        a, b = self._parse_key(key)
        a_inv = self.mod_inverse(a, self.alphabet_size)
        cleaned_text = self.clean_text(ciphertext)
        decrypted = ""
        
        for char in cleaned_text:
            if char in self.alphabet:
                y = self.alphabet.index(char)
                decrypted_index = (a_inv * (y - b)) % self.alphabet_size
                decrypted += self.alphabet[decrypted_index]
        
        return decrypted
