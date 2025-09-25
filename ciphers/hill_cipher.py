from .base_cipher import BaseCipher
import numpy as np
from math import gcd

class HillCipher(BaseCipher):
    """Implementation of Hill Cipher"""
    
    def _parse_key_matrix(self, key: str, size: int = 2) -> np.ndarray:
        """Parse key string into matrix"""
        try:
            elements = [int(x.strip()) for x in key.split(',')]
            if len(elements) != size * size:
                raise ValueError(f"Hill cipher key must contain {size*size} numbers for {size}x{size} matrix")
            
            matrix = np.array(elements).reshape(size, size)
            
            # Check if matrix is invertible modulo 26
            det = int(np.round(np.linalg.det(matrix))) % self.alphabet_size
            if gcd(det, self.alphabet_size) != 1:
                raise ValueError("Key matrix is not invertible modulo 26")
            
            return matrix
        except ValueError as e:
            if "invalid literal" in str(e):
                raise ValueError("Hill cipher key must contain only numbers separated by commas")
            raise e
    
    def _matrix_mod_inverse(self, matrix: np.ndarray) -> np.ndarray:
        """Calculate matrix inverse modulo 26"""
        det = int(np.round(np.linalg.det(matrix))) % self.alphabet_size
        det_inv = self.mod_inverse(det, self.alphabet_size)
        
        # Calculate adjugate matrix
        if matrix.shape[0] == 2:
            adj = np.array([[matrix[1,1], -matrix[0,1]], 
                           [-matrix[1,0], matrix[0,0]]])
        else:
            # For larger matrices, use numpy's inverse and convert
            adj = np.round(np.linalg.inv(matrix) * np.linalg.det(matrix)).astype(int)
        
        inv_matrix = (det_inv * adj) % self.alphabet_size
        return inv_matrix
    
    def _text_to_vectors(self, text: str, size: int) -> list:
        """Convert text to numerical vectors"""
        # Pad text if necessary
        while len(text) % size != 0:
            text += 'X'
        
        vectors = []
        for i in range(0, len(text), size):
            vector = []
            for j in range(size):
                char = text[i + j]
                vector.append(self.alphabet.index(char))
            vectors.append(np.array(vector))
        
        return vectors
    
    def _vectors_to_text(self, vectors: list) -> str:
        """Convert numerical vectors back to text"""
        text = ""
        for vector in vectors:
            for num in vector:
                text += self.alphabet[num % self.alphabet_size]
        return text
    
    def encrypt(self, plaintext: str, key: str) -> str:
        # Default to 2x2 matrix for simplicity
        matrix_size = 2
        key_matrix = self._parse_key_matrix(key, matrix_size)
        cleaned_text = self.clean_text(plaintext)
        
        if not cleaned_text:
            return ""
        
        vectors = self._text_to_vectors(cleaned_text, matrix_size)
        encrypted_vectors = []
        
        for vector in vectors:
            encrypted_vector = np.dot(key_matrix, vector) % self.alphabet_size
            encrypted_vectors.append(encrypted_vector)
        
        return self._vectors_to_text(encrypted_vectors)
    
    def decrypt(self, ciphertext: str, key: str) -> str:
        matrix_size = 2
        key_matrix = self._parse_key_matrix(key, matrix_size)
        inv_matrix = self._matrix_mod_inverse(key_matrix)
        cleaned_text = self.clean_text(ciphertext)
        
        if not cleaned_text:
            return ""
        
        vectors = self._text_to_vectors(cleaned_text, matrix_size)
        decrypted_vectors = []
        
        for vector in vectors:
            decrypted_vector = np.dot(inv_matrix, vector) % self.alphabet_size
            decrypted_vectors.append(decrypted_vector)
        
        return self._vectors_to_text(decrypted_vectors)
