import string
import random
import os
from typing import Dict, Any

class CryptoUtils:
    """Utility functions for cryptographic operations"""
    
    @staticmethod
    def analyze_text(text: str) -> Dict[str, Any]:
        """Analyze text for frequency analysis"""
        text = text.upper()
        alphabet = string.ascii_uppercase
        
        # Count frequencies
        freq_count = {char: 0 for char in alphabet}
        total_chars = 0
        
        for char in text:
            if char in alphabet:
                freq_count[char] += 1
                total_chars += 1
        
        # Calculate percentages
        freq_percent = {}
        for char in alphabet:
            freq_percent[char] = (freq_count[char] / total_chars * 100) if total_chars > 0 else 0
        
        # Sort by frequency
        sorted_freq = sorted(freq_percent.items(), key=lambda x: x[1], reverse=True)
        
        return {
            'total_characters': total_chars,
            'frequency_count': freq_count,
            'frequency_percent': freq_percent,
            'sorted_frequency': sorted_freq,
            'most_common': sorted_freq[0] if sorted_freq else ('', 0),
            'least_common': sorted_freq[-1] if sorted_freq else ('', 0)
        }
    
    @staticmethod
    def generate_random_key(cipher_type: str) -> str:
        """Generate random key for specified cipher type"""
        if cipher_type == 'shift':
            return str(random.randint(1, 25))
        
        elif cipher_type == 'substitution':
            alphabet = list(string.ascii_uppercase)
            random.shuffle(alphabet)
            return ''.join(alphabet)
        
        elif cipher_type == 'affine':
            # Generate coprime 'a' values
            coprime_values = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
            a = random.choice(coprime_values)
            b = random.randint(0, 25)
            return f"{a},{b}"
        
        elif cipher_type == 'vigenere':
            length = random.randint(3, 8)
            return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))
        
        elif cipher_type == 'hill':
            # Generate random 2x2 matrix with determinant coprime to 26
            while True:
                matrix = [random.randint(0, 25) for _ in range(4)]
                det = (matrix[0] * matrix[3] - matrix[1] * matrix[2]) % 26
                if CryptoUtils.gcd(det, 26) == 1:
                    return ','.join(map(str, matrix))
        
        elif cipher_type == 'permutation':
            length = random.randint(3, 8)
            return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))
        
        elif cipher_type == 'playfair':
            length = random.randint(5, 10)
            return ''.join(random.choice(string.ascii_uppercase) for _ in range(length))
        
        return ""
    
    @staticmethod
    def gcd(a: int, b: int) -> int:
        """Calculate Greatest Common Divisor"""
        while b:
            a, b = b, a % b
        return a
    
    @staticmethod
    def validate_key(cipher_type: str, key: str) -> Dict[str, Any]:
        """Validate key for specified cipher type"""
        result = {'valid': False, 'message': ''}
        
        try:
            if cipher_type == 'shift':
                num = int(key)
                if 0 <= num <= 25:
                    result['valid'] = True
                else:
                    result['message'] = 'Shift value must be between 0 and 25'
            
            elif cipher_type == 'substitution':
                key = key.upper().replace(' ', '')
                if len(key) == 26 and len(set(key)) == 26:
                    result['valid'] = True
                else:
                    result['message'] = 'Substitution key must contain 26 unique letters'
            
            elif cipher_type == 'affine':
                parts = key.split(',')
                if len(parts) == 2:
                    a, b = int(parts[0].strip()), int(parts[1].strip())
                    if CryptoUtils.gcd(a, 26) == 1:
                        result['valid'] = True
                    else:
                        result['message'] = f"'a' value ({a}) must be coprime with 26"
                else:
                    result['message'] = 'Affine key must be in format "a,b"'
            
            elif cipher_type in ['vigenere', 'permutation', 'playfair']:
                if key and key.replace(' ', '').isalpha():
                    result['valid'] = True
                else:
                    result['message'] = 'Key must contain only letters'
            
            elif cipher_type == 'hill':
                parts = key.split(',')
                if len(parts) == 4:
                    matrix = [int(x.strip()) for x in parts]
                    det = (matrix[0] * matrix[3] - matrix[1] * matrix[2]) % 26
                    if CryptoUtils.gcd(det, 26) == 1:
                        result['valid'] = True
                    else:
                        result['message'] = 'Matrix determinant must be coprime with 26'
                else:
                    result['message'] = 'Hill key must contain 4 numbers for 2x2 matrix'
            
        except ValueError:
            result['message'] = 'Invalid key format'
        except Exception as e:
            result['message'] = str(e)
        
        return result
