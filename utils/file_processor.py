import os
import mimetypes
import zipfile
import tempfile
from typing import List, Dict, Any
from werkzeug.utils import secure_filename

class FileProcessor:
    """Advanced file processing for cryptographic operations"""
    
    def __init__(self, base_path: str):
        self.base_path = base_path
        self.supported_text_extensions = {
            '.txt', '.md', '.py', '.js', '.html', '.css', '.json', '.xml', 
            '.csv', '.sql', '.php', '.java', '.cpp', '.c', '.h', '.rb', 
            '.go', '.rs', '.swift', '.kt', '.scala', '.pl', '.sh', '.bat'
        }
        self.supported_binary_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.zip', '.rar', '.7z', '.tar', '.gz', '.exe', '.dll', '.so',
            '.mp3', '.wav', '.mp4', '.avi', '.mov', '.mkv', '.flv'
        }
    
    def get_file_type(self, filename: str) -> str:
        """Determine file type based on extension"""
        ext = os.path.splitext(filename.lower())[1]
        
        if ext in self.supported_text_extensions:
            return 'text'
        elif ext in self.supported_binary_extensions:
            return 'binary'
        else:
            # Try to determine by content or default to binary
            return 'unknown'
    
    def process_file_for_encryption(self, file_path: str, cipher_type: str) -> Dict[str, Any]:
        """Process file for encryption with metadata preservation"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        filename = os.path.basename(file_path)
        file_type = self.get_file_type(filename)
        file_size = os.path.getsize(file_path)
        mime_type = mimetypes.guess_type(file_path)[0]
        
        # Read file content
        with open(file_path, 'rb') as f:
            content = f.read()
        
        # Create metadata
        metadata = {
            'original_filename': filename,
            'original_extension': os.path.splitext(filename)[1],
            'file_type': file_type,
            'file_size': file_size,
            'mime_type': mime_type,
            'cipher_type': cipher_type,
            'is_binary': file_type != 'text'
        }
        
        return {
            'content': content,
            'metadata': metadata,
            'filename': filename
        }
    
    def create_encrypted_file(self, encrypted_content: str, metadata: Dict[str, Any], output_path: str) -> str:
        """Create encrypted file with embedded metadata"""
        # Create metadata header
        metadata_lines = []
        for key, value in metadata.items():
            metadata_lines.append(f"{key.upper()}:{value}")
        
        metadata_header = '\n'.join(metadata_lines)
        
        # Combine metadata and encrypted content
        full_content = f"{metadata_header}\n---ENCRYPTED_CONTENT---\n{encrypted_content}"
        
        # Write to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(full_content)
        
        return output_path
    
    def parse_encrypted_file(self, file_path: str) -> Dict[str, Any]:
        """Parse encrypted file to extract metadata and content"""
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        if '---ENCRYPTED_CONTENT---' not in content:
            raise ValueError("Invalid encrypted file format")
        
        metadata_part, encrypted_content = content.split('---ENCRYPTED_CONTENT---\n', 1)
        
        # Parse metadata
        metadata = {}
        for line in metadata_part.strip().split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                # Convert boolean strings
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                # Convert numeric strings
                elif value.isdigit():
                    value = int(value)
                
                metadata[key.lower()] = value
        
        return {
            'metadata': metadata,
            'encrypted_content': encrypted_content.strip()
        }
    
    def restore_binary_file(self, decrypted_text: str, output_path: str) -> str:
        """Restore binary file from decrypted text representation"""
        binary_data = []
        i = 0
        
        while i < len(decrypted_text):
            if i + 3 < len(decrypted_text) and decrypted_text[i:i+2] == '\\x':
                # Hex encoded byte
                try:
                    hex_val = decrypted_text[i+2:i+4]
                    binary_data.append(int(hex_val, 16))
                    i += 4
                except ValueError:
                    # Invalid hex, treat as regular character
                    binary_data.append(ord(decrypted_text[i]))
                    i += 1
            else:
                # Regular ASCII character
                binary_data.append(ord(decrypted_text[i]))
                i += 1
        
        # Write binary data to file
        with open(output_path, 'wb') as f:
            f.write(bytes(binary_data))
        
        return output_path
    
    def create_download_package(self, files: List[str], package_name: str) -> str:
        """Create a ZIP package of multiple files"""
        package_path = os.path.join(self.base_path, f"{package_name}.zip")
        
        with zipfile.ZipFile(package_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for file_path in files:
                if os.path.exists(file_path):
                    arcname = os.path.basename(file_path)
                    zipf.write(file_path, arcname)
        
        return package_path
    
    def cleanup_temp_files(self, file_paths: List[str]) -> None:
        """Clean up temporary files"""
        for file_path in file_paths:
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
            except Exception:
                pass  # Ignore cleanup errors
    
    def get_file_info(self, file_path: str) -> Dict[str, Any]:
        """Get comprehensive file information"""
        if not os.path.exists(file_path):
            return None
        
        stat = os.stat(file_path)
        filename = os.path.basename(file_path)
        name, ext = os.path.splitext(filename)
        mime_type = mimetypes.guess_type(file_path)[0]
        file_type = self.get_file_type(filename)
        
        return {
            'filename': filename,
            'name': name,
            'extension': ext,
            'size': stat.st_size,
            'size_human': self._format_file_size(stat.st_size),
            'mime_type': mime_type,
            'file_type': file_type,
            'is_text': file_type == 'text',
            'is_binary': file_type != 'text',
            'created': stat.st_ctime,
            'modified': stat.st_mtime
        }
    
    def _format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"
        
        size_names = ["B", "KB", "MB", "GB", "TB"]
        i = 0
        while size_bytes >= 1024 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1
        
        return f"{size_bytes:.1f} {size_names[i]}"
