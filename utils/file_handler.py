import os
import base64
import mimetypes
from werkzeug.utils import secure_filename

class FileHandler:
    """Handle file operations for encryption/decryption"""
    
    def __init__(self, upload_folder):
        self.upload_folder = upload_folder
        self.allowed_extensions = {
            'text': ['.txt', '.md', '.py', '.html', '.css', '.js', '.json', '.xml', '.csv'],
            'binary': ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.docx', '.xlsx', '.zip', '.exe']
        }
    
    def is_text_file(self, filename):
        """Check if file is a text file based on extension"""
        ext = os.path.splitext(filename.lower())[1]
        return ext in self.allowed_extensions['text']
    
    def save_file(self, file, prefix=""):
        """Save uploaded file and return path"""
        if file and file.filename:
            filename = secure_filename(file.filename)
            if prefix:
                filename = f"{prefix}_{filename}"
            filepath = os.path.join(self.upload_folder, filename)
            file.save(filepath)
            return filepath
        return None
    
    def read_file(self, filepath):
        """Read file content"""
        try:
            with open(filepath, 'rb') as f:
                return f.read()
        except Exception as e:
            raise Exception(f"Error reading file: {str(e)}")
    
    def write_file(self, filepath, content, is_binary=False):
        """Write content to file"""
        try:
            mode = 'wb' if is_binary else 'w'
            encoding = None if is_binary else 'utf-8'
            
            with open(filepath, mode, encoding=encoding) as f:
                f.write(content)
            return filepath
        except Exception as e:
            raise Exception(f"Error writing file: {str(e)}")
    
    def get_file_info(self, filepath):
        """Get file information"""
        if not os.path.exists(filepath):
            return None
        
        stat = os.stat(filepath)
        filename = os.path.basename(filepath)
        ext = os.path.splitext(filename)[1]
        mime_type = mimetypes.guess_type(filepath)[0]
        
        return {
            'filename': filename,
            'size': stat.st_size,
            'extension': ext,
            'mime_type': mime_type,
            'is_text': self.is_text_file(filename)
        }
    
    def create_download_response(self, content, filename, is_binary=False):
        """Create response for file download"""
        if is_binary:
            return {
                'content': base64.b64encode(content).decode('utf-8'),
                'filename': filename,
                'is_binary': True
            }
        else:
            return {
                'content': content if isinstance(content, str) else content.decode('utf-8'),
                'filename': filename,
                'is_binary': False
            }
