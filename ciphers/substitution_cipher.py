from .base_cipher import BaseCipher
import string

class SubstitutionCipher(BaseCipher):
    """Implementation of Substitution Cipher"""
    
    def _validate_key(self, key: str) -> str:
        """Validate and prepare substitution key"""
        key = key.upper().replace(' ', '')
        
        if len(key) != self.alphabet_size:
            raise ValueError(f"Substitution key must be exactly {self.alphabet_size} characters long")
        
        if len(set(key)) != self.alphabet_size:
            raise ValueError("Substitution key must contain each letter exactly once")
        
        for char in key:
            if char not in self.alphabet:
                raise ValueError("Substitution key must contain only alphabetic characters")
        
        return key
    
    def encrypt(self, plaintext: str, key: str) -> str:
        key = self._validate_key(key)
        cleaned_text = self.clean_text(plaintext)
        encrypted = ""
        
        for char in cleaned_text:
            if char in self.alphabet:
                old_index = self.alphabet.index(char)
                encrypted += key[old_index]
        
        return encrypted
    
    def decrypt(self, ciphertext: str, key: str) -> str:
        key = self._validate_key(key)
        cleaned_text = self.clean_text(ciphertext)
        decrypted = ""
        
        for char in cleaned_text:
            if char in key:
                old_index = key.index(char)
                decrypted += self.alphabet[old_index]
        
        return decrypted
