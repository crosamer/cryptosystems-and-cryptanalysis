from .base_cipher import BaseCipher

class PlayfairCipher(BaseCipher):
    """Implementation of Playfair Cipher"""
    
    def __init__(self):
        super().__init__()
        self.alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"  # J is omitted, I/J treated as same
        self.alphabet_size = 25
    
    def _create_key_square(self, key: str) -> list:
        """Create 5x5 key square"""
        key = key.upper().replace('J', 'I')
        key_chars = []
        
        # Add unique characters from key
        for char in key:
            if char in self.alphabet and char not in key_chars:
                key_chars.append(char)
        
        # Add remaining alphabet characters
        for char in self.alphabet:
            if char not in key_chars:
                key_chars.append(char)
        
        # Create 5x5 square
        square = []
        for i in range(5):
            row = []
            for j in range(5):
                row.append(key_chars[i * 5 + j])
            square.append(row)
        
        return square
    
    def _find_position(self, char: str, square: list) -> tuple:
        """Find position of character in key square"""
        for i in range(5):
            for j in range(5):
                if square[i][j] == char:
                    return (i, j)
        return None
    
    def _prepare_text(self, text: str) -> str:
        """Prepare text for Playfair encryption"""
        text = self.clean_text(text).replace('J', 'I')
        prepared = ""
        
        i = 0
        while i < len(text):
            if i == len(text) - 1:
                # Last character, add X
                prepared += text[i] + 'X'
                i += 1
            elif text[i] == text[i + 1]:
                # Same characters, insert X
                prepared += text[i] + 'X'
                i += 1
            else:
                # Different characters
                prepared += text[i] + text[i + 1]
                i += 2
        
        return prepared
    
    def encrypt(self, plaintext: str, key: str) -> str:
        if not key:
            raise ValueError("Playfair cipher key cannot be empty")
        
        square = self._create_key_square(key)
        prepared_text = self._prepare_text(plaintext)
        encrypted = ""
        
        for i in range(0, len(prepared_text), 2):
            char1, char2 = prepared_text[i], prepared_text[i + 1]
            pos1 = self._find_position(char1, square)
            pos2 = self._find_position(char2, square)
            
            if pos1[0] == pos2[0]:  # Same row
                new_pos1 = (pos1[0], (pos1[1] + 1) % 5)
                new_pos2 = (pos2[0], (pos2[1] + 1) % 5)
            elif pos1[1] == pos2[1]:  # Same column
                new_pos1 = ((pos1[0] + 1) % 5, pos1[1])
                new_pos2 = ((pos2[0] + 1) % 5, pos2[1])
            else:  # Rectangle
                new_pos1 = (pos1[0], pos2[1])
                new_pos2 = (pos2[0], pos1[1])
            
            encrypted += square[new_pos1[0]][new_pos1[1]]
            encrypted += square[new_pos2[0]][new_pos2[1]]
        
        return encrypted
    
    def decrypt(self, ciphertext: str, key: str) -> str:
        if not key:
            raise ValueError("Playfair cipher key cannot be empty")
        
        square = self._create_key_square(key)
        cleaned_text = self.clean_text(ciphertext).replace('J', 'I')
        decrypted = ""
        
        for i in range(0, len(cleaned_text), 2):
            if i + 1 >= len(cleaned_text):
                break
                
            char1, char2 = cleaned_text[i], cleaned_text[i + 1]
            pos1 = self._find_position(char1, square)
            pos2 = self._find_position(char2, square)
            
            if pos1[0] == pos2[0]:  # Same row
                new_pos1 = (pos1[0], (pos1[1] - 1) % 5)
                new_pos2 = (pos2[0], (pos2[1] - 1) % 5)
            elif pos1[1] == pos2[1]:  # Same column
                new_pos1 = ((pos1[0] - 1) % 5, pos1[1])
                new_pos2 = ((pos2[0] - 1) % 5, pos2[1])
            else:  # Rectangle
                new_pos1 = (pos1[0], pos2[1])
                new_pos2 = (pos2[0], pos1[1])
            
            decrypted += square[new_pos1[0]][new_pos1[1]]
            decrypted += square[new_pos2[0]][new_pos2[1]]
        
        return decrypted
