import os
import pytest
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
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

def test_filetype():
    """Test file type validation"""
    # Test supported file extensions
    assert is_file_ok("test.pdf")
    assert is_file_ok("test.exe")
    assert is_file_ok("test.zip")
    assert is_file_ok("test.docx")
    assert is_file_ok("test.xlsx")
    
    # Test unsupported file extensions
    assert not is_file_ok("test.jpg")
    assert not is_file_ok("test.mp3")
    assert not is_file_ok("test.bmp")

def test_filehash():
    """Test file hash calculation"""
    test_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_file.txt')
    with open(test_file_path, 'w') as f:
        f.write("Test content")
    
    hash_result = get_hash(test_file_path)
    assert hash_result
    assert len(hash_result) == 64  # SHA256 hash length

def test_largefile():
    """Test large file handling"""
    test_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'large_file.txt')
    
    # Create a 2GB file (larger than our 1GB limit)
    with open(test_file_path, 'wb') as f:
        f.seek(2 * 1024 * 1024 * 1024 - 1)  # 2GB - 1 byte
        f.write(b'\0')
    
    # Test that the file is too large
    with pytest.raises(Exception) as exc_info:
        get_hash(test_file_path)
    assert "File too large" in str(exc_info.value)

def test_filedelete():
    """Test file cleanup"""
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

def test_supportedextensions():
    """Test supported file extensions"""
    # Test supported extensions
    assert 'pdf' in SUPPORTED_EXTENSIONS
    assert 'exe' in SUPPORTED_EXTENSIONS
    assert 'zip' in SUPPORTED_EXTENSIONS
    assert 'docx' in SUPPORTED_EXTENSIONS
    assert 'xlsx' in SUPPORTED_EXTENSIONS
    
    # Test unsupported extensions
    assert 'jpg' not in SUPPORTED_EXTENSIONS

# VirusTotal API Integration Tests


def test_filescanning():
    """Test file scanning with VirusTotal"""
    from app import scan_file_with_virustotal
    test_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_scan.txt')
    invalid_file_path = os.path.join(app.config['UPLOAD_FOLDER'], 'test_invalid.txt')
    
    # Create test files
    with open(test_file_path, 'w') as f:
        f.write("Test content")
    with open(invalid_file_path, 'w') as f:
        f.write("Invalid content")
    
    try:
        # Test with valid file
        result = scan_file_with_virustotal(test_file_path, 'test_scan.txt')
        assert 'status' in result
        assert 'malicious' in result
        assert 'risk_level' in result
        assert 'risk_score' in result
        assert result['status'] in ['analyzed', 'queued', 'error']
        
        # Test with invalid file type
        result = scan_file_with_virustotal(invalid_file_path, 'test_invalid.txt')
        assert 'status' in result
        assert 'malicious' in result
        assert 'risk_level' in result
        assert 'risk_score' in result
        assert result['status'] in ['analyzed', 'queued', 'error']
        
    finally:
        # Clean up test files
        if os.path.exists(test_file_path):
            os.remove(test_file_path)
        if os.path.exists(invalid_file_path):
            os.remove(invalid_file_path)
