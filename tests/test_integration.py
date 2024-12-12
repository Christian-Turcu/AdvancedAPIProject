import pytest
from pathlib import Path
import json
import os
from unittest.mock import patch
import io

def test_index_page(client):
    """Test the main page loads correctly"""
    response = client.get('/')
    assert response.status_code == 200
    assert b'Upload File for Analysis' in response.data

def test_file_too_large(client):
    """Test file size limit handling"""
    # Create a temporary file with content larger than the limit
    content = b'a' * (100 * 1024 * 1024 + 1)  # Just over 100MB
    temp_file = io.BytesIO(content)
    temp_file.seek(0)  # Ensure we're at the start
    
    # Create a FileStorage object with a proper tell() method
    class SizeAwareFileStorage:
        def __init__(self, stream, filename, content_type):
            self.stream = stream
            self.filename = filename
            self.content_type = content_type
            self._size = len(content)
        
        def tell(self):
            return self._size
        
        def seek(self, offset, whence=0):
            self.stream.seek(offset, whence)
        
        def read(self, size=-1):
            return self.stream.read(size)
        
        def save(self, dst):
            self.stream.seek(0)
            with open(dst, 'wb') as f:
                f.write(self.stream.read())
    
    file = SizeAwareFileStorage(temp_file, 'test.txt', 'text/plain')
    data = {'file': file}
    response = client.post('/analyze', data=data, headers={'Accept': 'application/json'})
    assert response.status_code == 413
    assert json.loads(response.data)['error'] == 'File too large'

def test_invalid_file_type(client):
    """Test invalid file type rejection"""
    data = {'file': (io.BytesIO(b'test content'), 'test.invalid')}
    response = client.post('/analyze', data=data, headers={'Accept': 'application/json'})
    assert response.status_code == 400
    assert json.loads(response.data)['error'] == 'Unsupported file type'

@pytest.mark.skipif(not os.getenv('VIRUS_TOTAL_API_KEY'),
                    reason="No API key provided")
def test_file_upload_and_scan(client, test_file):
    """Test file upload and scanning"""
    with open(test_file, 'rb') as f:
        data = {'file': (f, 'test.txt')}
        response = client.post('/analyze', data=data, headers={'Accept': 'application/json'})

    assert response.status_code == 200
    result = json.loads(response.data)
    assert result['filename'] == 'test.txt'
    assert result['status'] in ['queued', 'analyzed']

@patch('app.requests.get')
@patch('app.requests.post')
def test_file_scan_mocked(mock_post, mock_get, client, test_file, mock_vt_response):
    """Test file scanning with mocked VirusTotal API"""
    # Mock the file hash lookup
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = mock_vt_response

    # Mock the file upload response
    mock_post.return_value.status_code = 200
    mock_post.return_value.json.return_value = {
        'data': {
            'id': 'test_analysis_id',
            'type': 'analysis'
        }
    }

    with open(test_file, 'rb') as f:
        data = {'file': (f, 'test.txt')}
        response = client.post('/analyze', data=data, headers={'Accept': 'application/json'})

    assert response.status_code == 200
    result = json.loads(response.data)
    assert result['filename'] == 'test.txt'
    assert result['status'] in ['queued', 'analyzed']

def test_folder_analysis(client, tmp_path):
    """Test folder upload and analysis"""
    # Create test files in temporary directory
    (tmp_path / 'test1.txt').write_text('test content 1')
    (tmp_path / 'test2.txt').write_text('test content 2')

    # Create zip file
    import zipfile
    zip_path = tmp_path / 'test_folder.zip'
    with zipfile.ZipFile(zip_path, 'w') as zip_file:
        zip_file.write(tmp_path / 'test1.txt', 'test1.txt')
        zip_file.write(tmp_path / 'test2.txt', 'test2.txt')

    with open(zip_path, 'rb') as f:
        data = {'file': (f, 'test_folder.zip')}
        response = client.post('/analyze', data=data, headers={'Accept': 'application/json'})

    assert response.status_code == 200
    result = json.loads(response.data)
    assert result['filename'] == 'test_folder.zip'
    assert result['is_folder'] == True
    assert len(result['files']) == 2
