from flask import Flask, render_template, request, jsonify, send_file, flash, redirect, url_for, make_response
import os
import io
import base64
from werkzeug.utils import secure_filename
from ciphers.shift_cipher import ShiftCipher
from ciphers.substitution_cipher import SubstitutionCipher
from ciphers.affine_cipher import AffineCipher
from ciphers.vigenere_cipher import VigenereCipher
from ciphers.hill_cipher import HillCipher
from ciphers.permutation_cipher import PermutationCipher
from ciphers.onetimepad_cipher import OneTimePadCipher
from ciphers.playfair_cipher import PlayfairCipher
from utils.file_handler import FileHandler
from utils.crypto_utils import CryptoUtils
from utils.file_processor import FileProcessor

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ENCRYPTED_FOLDER'] = 'encrypted'
app.config['TEMP_FOLDER'] = 'temp'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Ensure directories exist
for folder in [app.config['UPLOAD_FOLDER'], app.config['ENCRYPTED_FOLDER'], app.config['TEMP_FOLDER']]:
    os.makedirs(folder, exist_ok=True)

# Initialize handlers
file_handler = FileHandler(app.config['UPLOAD_FOLDER'])
file_processor = FileProcessor(app.config['ENCRYPTED_FOLDER'])

# Initialize cipher classes
ciphers = {
    'shift': ShiftCipher(),
    'substitution': SubstitutionCipher(),
    'affine': AffineCipher(),
    'vigenere': VigenereCipher(),
    'hill': HillCipher(),
    'permutation': PermutationCipher(),
    'onetimepad': OneTimePadCipher(),
    'playfair': PlayfairCipher()
}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/file_info', methods=['POST'])
def get_file_info():
    """Get information about uploaded file"""
    try:
        file = request.files.get('file')
        if not file or not file.filename:
            return jsonify({'error': 'No file provided'}), 400
        
        # Save temporary file
        temp_path = os.path.join(app.config['TEMP_FOLDER'], secure_filename(file.filename))
        file.save(temp_path)
        
        # Get file info
        info = file_processor.get_file_info(temp_path)
        
        # Cleanup
        file_processor.cleanup_temp_files([temp_path])
        
        return jsonify({'success': True, 'file_info': info})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/batch_encrypt', methods=['POST'])
def batch_encrypt():
    """Encrypt multiple files at once"""
    try:
        cipher_type = request.form.get('cipher_type')
        key = request.form.get('key', '')
        files = request.files.getlist('files')
        
        if cipher_type not in ciphers:
            return jsonify({'error': 'Invalid cipher type'}), 400
        
        if not files:
            return jsonify({'error': 'No files provided'}), 400
        
        # Validate key
        validation = CryptoUtils.validate_key(cipher_type, key)
        if not validation['valid']:
            return jsonify({'error': f'Invalid key: {validation["message"]}'}), 400
        
        cipher = ciphers[cipher_type]
        encrypted_files = []
        
        for file in files:
            if file.filename:
                # Process each file
                temp_path = os.path.join(app.config['TEMP_FOLDER'], secure_filename(file.filename))
                file.save(temp_path)
                
                # Process file
                file_data = file_processor.process_file_for_encryption(temp_path, cipher_type)
                
                # Encrypt content
                if file_data['metadata']['is_binary']:
                    # Binary file
                    text_repr = ''.join(chr(b) if b < 128 else f'\\x{b:02x}' for b in file_data['content'])
                    encrypted_content = cipher.encrypt(text_repr, key)
                else:
                    # Text file
                    content_str = file_data['content'].decode('utf-8')
                    encrypted_content = cipher.encrypt(content_str, key)
                
                # Save encrypted file
                encrypted_filename = f"encrypted_{os.path.splitext(file_data['filename'])[0]}.dat"
                encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_filename)
                
                file_processor.create_encrypted_file(encrypted_content, file_data['metadata'], encrypted_path)
                encrypted_files.append(encrypted_path)
                
                # Cleanup temp file
                file_processor.cleanup_temp_files([temp_path])
        
        # Create ZIP package
        package_path = file_processor.create_download_package(encrypted_files, f"batch_encrypted_{cipher_type}")
        
        return jsonify({
            'success': True,
            'encrypted_count': len(encrypted_files),
            'package_url': f'/download/package/{os.path.basename(package_path)}'
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/package/<filename>')
def download_package(filename):
    """Download ZIP package"""
    try:
        filepath = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=filename)
        else:
            return jsonify({'error': 'Package not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/generate_key/<cipher_type>')
def generate_key(cipher_type):
    """Generate random key for specified cipher"""
    try:
        if cipher_type not in ciphers:
            return jsonify({'error': 'Invalid cipher type'}), 400
        
        key = CryptoUtils.generate_random_key(cipher_type)
        return jsonify({'success': True, 'key': key})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/validate_key', methods=['POST'])
def validate_key():
    """Validate key for specified cipher"""
    try:
        cipher_type = request.json.get('cipher_type')
        key = request.json.get('key', '')
        
        validation = CryptoUtils.validate_key(cipher_type, key)
        return jsonify(validation)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/analyze_text', methods=['POST'])
def analyze_text():
    """Analyze text for frequency analysis"""
    try:
        text = request.json.get('text', '')
        analysis = CryptoUtils.analyze_text(text)
        return jsonify({'success': True, 'analysis': analysis})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/generate_otp_key', methods=['POST'])
def generate_otp_key():
    """Generate One-Time Pad key file"""
    try:
        length = int(request.json.get('length', 10000))
        filename = request.json.get('filename', 'otp_key.txt')
        
        otp_cipher = ciphers['onetimepad']
        filepath = otp_cipher.generate_key_file(length, filename)
        
        return jsonify({
            'success': True,
            'filepath': filepath,
            'message': f'OTP key file generated: {filename}'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        cipher_type = request.form.get('cipher_type')
        text_input = request.form.get('text_input', '')
        key = request.form.get('key', '')
        file = request.files.get('file')
        
        if cipher_type not in ciphers:
            return jsonify({'error': 'Invalid cipher type'}), 400
        
        # Validate key first
        validation = CryptoUtils.validate_key(cipher_type, key)
        if not validation['valid']:
            return jsonify({'error': f'Invalid key: {validation["message"]}'}), 400
        
        cipher = ciphers[cipher_type]
        
        if file and file.filename:
            # File encryption using FileProcessor
            temp_path = os.path.join(app.config['TEMP_FOLDER'], secure_filename(file.filename))
            file.save(temp_path)
            
            # Process file
            file_data = file_processor.process_file_for_encryption(temp_path, cipher_type)
            
            # Encrypt content
            if file_data['metadata']['is_binary']:
                # Binary file
                text_repr = ''.join(chr(b) if b < 128 else f'\\x{b:02x}' for b in file_data['content'])
                encrypted_content = cipher.encrypt(text_repr, key)
            else:
                # Text file
                content_str = file_data['content'].decode('utf-8')
                encrypted_content = cipher.encrypt(content_str, key)
            
            # Save encrypted file
            encrypted_filename = f"encrypted_{os.path.splitext(file_data['filename'])[0]}.dat"
            encrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], encrypted_filename)
            
            file_processor.create_encrypted_file(encrypted_content, file_data['metadata'], encrypted_path)
            
            # Cleanup temp file
            file_processor.cleanup_temp_files([temp_path])
            
            return jsonify({
                'success': True,
                'encrypted_text': encrypted_content if not file_data['metadata']['is_binary'] else None,
                'encrypted_data': base64.b64encode(encrypted_content.encode()).decode() if file_data['metadata']['is_binary'] else None,
                'is_file': True,
                'is_binary': file_data['metadata']['is_binary'],
                'filename': file_data['filename'],
                'encrypted_filename': encrypted_filename,
                'download_url': f'/download/encrypted/{encrypted_filename}',
                'file_info': file_data['metadata']
            })
        
        elif text_input:
            # Text encryption
            encrypted = cipher.encrypt(text_input, key)
            return jsonify({
                'success': True,
                'encrypted_text': encrypted,
                'is_file': False
            })
        
        else:
            return jsonify({'error': 'No input provided'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        cipher_type = request.form.get('cipher_type')
        encrypted_input = request.form.get('encrypted_input', '')
        key = request.form.get('key', '')
        file = request.files.get('encrypted_file')
        
        if cipher_type not in ciphers:
            return jsonify({'error': 'Invalid cipher type'}), 400
        
        cipher = ciphers[cipher_type]
        
        if file and file.filename:
            # File decryption using FileProcessor
            temp_path = os.path.join(app.config['TEMP_FOLDER'], secure_filename(file.filename))
            file.save(temp_path)
            
            # Parse encrypted file
            parsed_data = file_processor.parse_encrypted_file(temp_path)
            metadata = parsed_data['metadata']
            encrypted_content = parsed_data['encrypted_content']
            
            # Decrypt content
            decrypted = cipher.decrypt(encrypted_content, key)
            
            # Restore file
            if metadata.get('is_binary'):
                # Binary file
                decrypted_filename = metadata.get('original_filename', 'decrypted_file')
                decrypted_path = os.path.join(app.config['ENCRYPTED_FOLDER'], f"decrypted_{decrypted_filename}")
                
                file_processor.restore_binary_file(decrypted, decrypted_path)
                
                # Cleanup temp file
                file_processor.cleanup_temp_files([temp_path])
                
                return jsonify({
                    'success': True,
                    'decrypted_file': True,
                    'original_filename': metadata.get('original_filename'),
                    'download_url': f'/download/decrypted/{os.path.basename(decrypted_path)}',
                    'file_info': metadata
                })
            else:
                # Text file
                file_processor.cleanup_temp_files([temp_path])
                
                return jsonify({
                    'success': True,
                    'decrypted_text': decrypted,
                    'original_filename': metadata.get('original_filename'),
                    'file_info': metadata
                })
        
        elif encrypted_input:
            # Text decryption
            decrypted = cipher.decrypt(encrypted_input, key)
            return jsonify({
                'success': True,
                'decrypted_text': decrypted
            })
        
        else:
            return jsonify({'error': 'No input provided'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/encrypted/<filename>')
def download_encrypted(filename):
    try:
        filepath = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=filename)
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/decrypted/<filename>')
def download_decrypted(filename):
    try:
        filepath = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
        if os.path.exists(filepath):
            return send_file(filepath, as_attachment=True, download_name=filename.replace('decrypted_', ''))
        else:
            return jsonify({'error': 'File not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Cleanup endpoint for removing old files
@app.route('/cleanup', methods=['POST'])
def cleanup_files():
    """Clean up old temporary and encrypted files"""
    try:
        import time
        current_time = time.time()
        cleanup_age = 24 * 60 * 60  # 24 hours
        
        cleaned_files = 0
        
        # Clean temp files
        for filename in os.listdir(app.config['TEMP_FOLDER']):
            filepath = os.path.join(app.config['TEMP_FOLDER'], filename)
            if os.path.isfile(filepath):
                file_age = current_time - os.path.getctime(filepath)
                if file_age > cleanup_age:
                    os.remove(filepath)
                    cleaned_files += 1
        
        # Clean old encrypted files
        for filename in os.listdir(app.config['ENCRYPTED_FOLDER']):
            if filename.endswith('.zip'):  # Only clean package files
                filepath = os.path.join(app.config['ENCRYPTED_FOLDER'], filename)
                if os.path.isfile(filepath):
                    file_age = current_time - os.path.getctime(filepath)
                    if file_age > cleanup_age:
                        os.remove(filepath)
                        cleaned_files += 1
        
        return jsonify({
            'success': True,
            'cleaned_files': cleaned_files,
            'message': f'Cleaned up {cleaned_files} old files'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
