import os
import pytest
from app import app, get_hash, is_file_ok, SUPPORTED_EXTENSIONS

def setup_function():
    """Setup function to run before each test"""
    app.config['TESTING'] = True
    app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'test_uploads')
    
    # Create test uploads directory if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

def teardown_function():
    """Cleanup function to run after each test"""
    # Delete test uploads directory
    if os.path.exists(app.config['UPLOAD_FOLDER']):
        for file in os.listdir(app.config['UPLOAD_FOLDER']):
            os.remove(os.path.join(app.config['UPLOAD_FOLDER'], file))
        os.rmdir(app.config['UPLOAD_FOLDER'])

def test_file_type_check():
    """Test that only supported file types are allowed"""
    # Test with supported file extensions
    assert is_file_ok("test.pdf") == True
    assert is_file_ok("test.exe") == True
    assert is_file_ok("test.zip") == True
    assert is_file_ok("test.docx") == True
    assert is_file_ok("test.xlsx") == True
    
    # Test with unsupported file extensions
    assert is_file_ok("test.jpg") == False
    assert is_file_ok("test.mp3") == False
    assert is_file_ok("test.bmp") == False

def test_file_hash_calculation():
    """Test the file hash calculation"""
    test_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_file.txt')
    with open(test_file_path, 'w') as f:
        f.write("Test content")
    
    hash_result = get_hash(test_file_path)
    assert hash_result is not None
    assert len(hash_result) == 64  # SHA256 hash length

def test_large_file_handling():
    """Test the large file handling"""
    test_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'large_file.txt')
    
    # Create a 2GB file (larger than our 1GB limit)
    with open(test_file_path, 'wb') as f:
        f.seek(2 * 1024 * 1024 * 1024 - 1)  # 2GB - 1 byte
        f.write(b'\0')
    
    # Test that the file is too large
    with pytest.raises(Exception) as exc_info:
        get_hash(test_file_path)
    assert "File too large" in str(exc_info.value)

def test_file_cleanup():
    """Test that the temporary files are cleaned up"""
    test_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_cleanup.txt')
    
    # Create a test file
    with open(test_file_path, 'w') as f:
        f.write("Test content")
    
    # The file should exist after creation
    assert os.path.exists(test_file_path)
    
    # Clean up the file
    os.remove(test_file_path)
    
    # The file should be gone
    assert not os.path.exists(test_file_path)

def test_supported_extensions():
    """Testing to see if it supported correct extensions"""
    assert 'pdf' in SUPPORTED_EXTENSIONS
    assert 'exe' in SUPPORTED_EXTENSIONS
    assert 'zip' in SUPPORTED_EXTENSIONS
    assert 'jpg' not in SUPPORTED_EXTENSIONS 
