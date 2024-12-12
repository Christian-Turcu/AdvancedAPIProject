import pytest
from app import app as flask_app
import os
import tempfile
from pathlib import Path

@pytest.fixture
def app():
    # Create a temporary directory for test uploads
    with tempfile.TemporaryDirectory() as temp_dir:
        flask_app.config['UPLOAD_FOLDER'] = temp_dir
        flask_app.config['TESTING'] = True
        yield flask_app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

@pytest.fixture
def test_file():
    # Create a temporary test file
    with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
        f.write(b'Test content for file scanning')
        return Path(f.name)

@pytest.fixture
def mock_vt_response():
    return {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "harmless": 70,
                    "malicious": 0,
                    "suspicious": 0,
                    "undetected": 10,
                    "timeout": 0
                },
                "last_analysis_results": {
                    "scanner1": {
                        "category": "harmless",
                        "result": None
                    },
                    "scanner2": {
                        "category": "undetected",
                        "result": None
                    }
                },
                "last_analysis_date": 1638360000
            }
        }
    }
