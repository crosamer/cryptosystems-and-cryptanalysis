from .base_cipher import BaseCipher

class PermutationCipher(BaseCipher):
    """Implementation of Permutation Cipher (Columnar Transposition)"""
    
    def _get_key_order(self, key: str) -> list:
        """Get the order of columns based on alphabetical sorting of key"""
        key = key.upper()
        sorted_key = sorted(enumerate(key), key=lambda x: x[1])
        return [x[0] for x in sorted_key]
    
    def _create_grid(self, text: str, key_length: int) -> list:
        """Create grid for transposition"""
        # Pad text if necessary
        while len(text) % key_length != 0:
            text += 'X'
        
        grid = []
        for i in range(0, len(text), key_length):
            grid.append(list(text[i:i + key_length]))
        
        return grid
    
    def encrypt(self, plaintext: str, key: str) -> str:
        if not key:
            raise ValueError("Permutation cipher key cannot be empty")
        
        cleaned_text = self.clean_text(plaintext)
        if not cleaned_text:
            return ""
        
        key_order = self._get_key_order(key)
        grid = self._create_grid(cleaned_text, len(key))
        
        encrypted = ""
        # Read columns in key order
        for col_index in key_order:
            for row in grid:
                if col_index < len(row):
                    encrypted += row[col_index]
        
        return encrypted
    
    def decrypt(self, ciphertext: str, key: str) -> str:
        if not key:
            raise ValueError("Permutation cipher key cannot be empty")
        
        cleaned_text = self.clean_text(ciphertext)
        if not cleaned_text:
            return ""
        
        key_order = self._get_key_order(key)
        key_length = len(key)
        num_rows = len(cleaned_text) // key_length
        
        # Create empty grid
        grid = [[''] * key_length for _ in range(num_rows)]
        
        # Fill grid column by column in key order
        text_index = 0
        for col_index in key_order:
            for row in range(num_rows):
                if text_index < len(cleaned_text):
                    grid[row][col_index] = cleaned_text[text_index]
                    text_index += 1
        
        # Read grid row by row
        decrypted = ""
        for row in grid:
            decrypted += ''.join(row)
        
        return decrypted
