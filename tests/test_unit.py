import pytest
from pathlib import Path
from app import (
    is_file_ok,
    calc_score,
    get_hash,
    validate_api_key,
    check_upload_folder
)
import tempfile
import os
import hashlib

def test_is_file_ok():
    """Test file extension validation"""
    assert is_file_ok('test.txt') == True
    assert is_file_ok('test.pdf') == True
    assert is_file_ok('test.exe') == True
    assert is_file_ok('test.invalid') == False
    assert is_file_ok('noextension') == False

def test_calc_score():
    """Test risk score calculation"""
    # Test safe file
    score, level = calc_score(0, 80)
    assert score == 0
    assert level == "Safe"

    # Test low risk file
    score, level = calc_score(20, 80)
    assert score <= 35
    assert level == "Low"

    # Test medium risk file
    score, level = calc_score(40, 80)
    assert 35 < score <= 69
    assert level == "Medium"

    # Test high risk file
    score, level = calc_score(70, 80)
    assert score > 69
    assert level == "High"

def test_get_hash(test_file):
    """Test file hash calculation"""
    # Calculate hash manually
    with open(test_file, 'rb') as f:
        content = f.read()
    expected_hash = hashlib.sha256(content).hexdigest()
    
    # Compare with function result
    assert get_hash(test_file) == expected_hash

def test_check_upload_folder(app):
    """Test upload folder validation"""
    with tempfile.TemporaryDirectory() as temp_dir:
        app.config['UPLOAD_FOLDER'] = temp_dir
        assert check_upload_folder() == True

    # Test with non-existent folder
    app.config['UPLOAD_FOLDER'] = '/nonexistent/folder'
    assert check_upload_folder() == False

@pytest.mark.skipif(not os.getenv('VIRUS_TOTAL_API_KEY'), 
                    reason="No API key provided")
def test_validate_api_key():
    """Test API key validation"""
    assert validate_api_key() == True
