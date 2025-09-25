from .base_cipher import BaseCipher

class VigenereCipher(BaseCipher):
    """Implementation of Vigenere Cipher"""
    
    def _prepare_key(self, key: str, text_length: int) -> str:
        """Prepare key to match text length"""
        key = self.clean_text(key)
        if not key:
            raise ValueError("Vigenere cipher key cannot be empty")
        
        # Repeat key to match text length
        repeated_key = ""
        for i in range(text_length):
            repeated_key += key[i % len(key)]
        
        return repeated_key
    
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
