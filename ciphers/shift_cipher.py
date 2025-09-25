from .base_cipher import BaseCipher

class ShiftCipher(BaseCipher):
    """Implementation of Caesar/Shift Cipher"""
    
    def encrypt(self, plaintext: str, key: str) -> str:
        try:
            shift = int(key) % self.alphabet_size
        except ValueError:
            raise ValueError("Shift cipher key must be a number")
        
        cleaned_text = self.clean_text(plaintext)
        encrypted = ""
        
        for char in cleaned_text:
            if char in self.alphabet:
                old_index = self.alphabet.index(char)
                new_index = (old_index + shift) % self.alphabet_size
                encrypted += self.alphabet[new_index]
        
        return encrypted
    
    def decrypt(self, ciphertext: str, key: str) -> str:
        try:
            shift = int(key) % self.alphabet_size
        except ValueError:
            raise ValueError("Shift cipher key must be a number")
        
        cleaned_text = self.clean_text(ciphertext)
        decrypted = ""
        
        for char in cleaned_text:
            if char in self.alphabet:
                old_index = self.alphabet.index(char)
                new_index = (old_index - shift) % self.alphabet_size
                decrypted += self.alphabet[new_index]
        
        return decrypted
