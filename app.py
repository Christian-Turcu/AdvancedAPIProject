import os
import time
import json
import hashlib
import shutil
import zipfile
from pathlib import Path
import requests
from flask import Flask, render_template, request, jsonify, redirect
from werkzeug.utils import secure_filename #*** Secure Filename Handling with Werkzeug ***
from dotenv import load_dotenv #*** Environment Variables for the Sensitive Data ***
import tempfile
import logging
from urllib.request import urlopen

# Load the config
load_dotenv()

# Set up Flask app
app = Flask(__name__)

# Initialize Flask app
app.config['UPLOAD_FOLDER'] = os.path.join(os.getcwd(), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max file size
app.config['SECRET_KEY'] = os.urandom(24)

# Add JSON encoder for undefined values
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        try:
            return json.JSONEncoder.default(self, obj)
        except TypeError:
            return str(obj)

app.json_encoder = CustomJSONEncoder

# Add tojson filter to Jinja2
def safe_tojson(obj):
    return json.dumps(obj, cls=CustomJSONEncoder)

app.jinja_env.filters['tojson'] = safe_tojson

# Configure logging
logging.basicConfig(level=logging.INFO)

# Basic app settings + Max is 1GB for scanning a file
UPLOAD_FOLDER = Path(__file__).parent / 'uploads'
# Remove MAX_FILE_SIZE since we're using MAX_CONTENT_LENGTH

# Configure Flask app
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create uploads folder if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# The Types of files it can handle
SUPPORTED_EXTENSIONS = {
    'txt', 'pdf', 'doc', 'docx',  # Common documents
    'xls', 'xlsx',                # Excel files
    'exe', 'dll',                 # Executables
    'zip', 'rar', '7z',           # Archives
    'tar', 'gz'                   # Compressed files
}

app.config.update(
    UPLOAD_FOLDER=UPLOAD_FOLDER,
    ALLOWED_EXTENSIONS=SUPPORTED_EXTENSIONS
)

# VirusTotal API configuration *** Environment Variables for the Sensitive Data ***
vt_config = {
    'key': os.getenv('VIRUS_TOTAL_API_KEY'),
    'base': 'https://www.virustotal.com/api/v3',
    'headers': {
        'x-apikey': os.getenv('VIRUS_TOTAL_API_KEY'),
        'accept': 'application/json'
    }
}

# Handles The large files
@app.errorhandler(413)
def file_too_large(error):
    return render_template(
        'error.html',
        error_message="The File is to Big",
        error_details="The File/folder should be under 1GB."
    ), 413

@app.errorhandler(413)
def request_entity_too_large(error):
    """Handle request entity too large error"""
    app.logger.error("File too large")
    if request.headers.get('Accept') == 'application/json':
        return jsonify({"error": "File too large"}), 413
    return render_template('error.html', error="File too large"), 413

@app.before_request
def check_file_size():
    """Check file size before processing request"""
    if request.method == 'POST' and 'file' in request.files:
        file = request.files['file']
        size = get_file_size(file)
        
        if size is not None and size > app.config['MAX_CONTENT_LENGTH']:
            app.logger.error(f"File too large: {size} bytes")
            if request.headers.get('Accept') == 'application/json':
                return jsonify({"error": "File too large"}), 413
            return render_template('error.html', error="File too large"), 413



def is_file_ok(filename):
    """Check if the file type is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in SUPPORTED_EXTENSIONS

def check_upload_folder():
    """This Makes sure we can write to uploads folder"""
    try:
        upload_path = Path(app.config['UPLOAD_FOLDER'])
        if not upload_path.exists():
            return False
        upload_path.mkdir(exist_ok=True)
        return upload_path.is_dir() and os.access(upload_path, os.W_OK)
    except Exception as e:
        app.logger.error(f"Upload folder issues: {e}")
        return False

def calc_score(detected, total_scanners):
    """Calculate risk score and level based on detections"""
    if total_scanners == 0:
        return 0, 'Safe'
    
    score = (detected / total_scanners) * 100
    
    if score > 69:
        level = 'High'
    elif score > 35:
        level = 'Medium'
    elif score > 0:
        level = 'Low'
    else:
        level = 'Safe'
    
    return round(score, 2), level

def process_large_file(file_path, chunk_size=8388608):  # 8MB chunks
    """Process large files in chunks to avoid memory issues"""
    try:
        hash_md5 = hashlib.md5()
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hash_md5.update(chunk)
                
        return hash_md5.hexdigest()
    except Exception as e:
        app.logger.error(f"Error processing large file: {str(e)}")
        return None

def get_hash(file_path):
    """Get SHA256 hash of file, using chunked processing for large files"""
    try:
        file_size = os.path.getsize(file_path)
        
        # Check if file is too large
        if file_size > app.config['MAX_CONTENT_LENGTH']:
            raise Exception(f"File too large: {file_size} bytes")
            
        # For files larger than 100MB, use chunked processing
        if file_size > 100 * 1024 * 1024:  # 100MB
            app.logger.info(f"Processing large file ({file_size} bytes) in chunks")
            hash_sha256 = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8 * 1024 * 1024)  # 8MB chunks
                    if not chunk:
                        break
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
            
        # For smaller files, process normally
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            hash_sha256.update(f.read())
        return hash_sha256.hexdigest()
    except Exception as e:
        app.logger.error(f"Error calculating file hash: {str(e)}")
        raise

def get_file_size(file_obj):
    """Get size of file object safely"""
    try:
        # Try to get size using tell()
        file_obj.seek(0, 2)  # Seek to end
        size = file_obj.tell()
        file_obj.seek(0)  # Reset to beginning
        return size
    except (AttributeError, IOError):
        # If seek/tell not supported, try to get content length
        try:
            return len(file_obj.read())
        except (AttributeError, IOError):
            return None
        finally:
            try:
                file_obj.seek(0)
            except (AttributeError, IOError):
                pass

def is_file_too_large(file_obj):
    """Check if file is too large"""
    try:
        # Save current position
        pos = file_obj.tell()
        
        # Try to read more than the maximum allowed size
        chunk = file_obj.read(app.config['MAX_CONTENT_LENGTH'] + 1)
        size = len(chunk)
        
        # Restore position
        file_obj.seek(pos)
        
        return size > app.config['MAX_CONTENT_LENGTH']
    except Exception as e:
        app.logger.error(f"Error checking file size: {str(e)}")
        return False

def upload_large_file(file_path, upload_url, filename):
    """Upload large files using requests with stream=True"""
    try:
        with open(file_path, 'rb') as f:
            files = {'file': (filename, f)}
            response = requests.post(upload_url, files=files, headers=vt_config['headers'])
            return response
    except Exception as e:
        app.logger.error(f"Error uploading file: {str(e)}")
        return None

def analyze_zip(file_path):
    """Analyze contents of a ZIP file"""
    try:
        app.logger.info(f"Starting ZIP analysis for: {file_path}")
        
        results = []
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            temp_dir = tempfile.mkdtemp()
            try:
                app.logger.info(f"Extracting ZIP to temp directory: {temp_dir}")
                zip_ref.extractall(temp_dir)
                
                for root, _, files in os.walk(temp_dir):
                    for file in files:
                        full_path = os.path.join(root, file)
                        app.logger.info(f"Processing file from ZIP: {file}")
                        try:
                            scan_result = scan_file_with_virustotal(full_path, file)
                            app.logger.info(f"Scan result for {file}: {scan_result}")
                            
                            if scan_result is None:
                                app.logger.warning(f"Scan returned None for {file}")
                                scan_result = {
                                    'status': 'error',
                                    'error': 'Scan failed',
                                    'malicious': 0,
                                    'undetected': 0,
                                    'risk_level': 'Unknown',
                                    'risk_score': 0
                                }
                            
                            file_result = {
                                'filename': file,
                                'scan_result': scan_result
                            }
                            app.logger.info(f"Adding result for {file}: {file_result}")
                            results.append(file_result)
                            
                        except Exception as e:
                            app.logger.error(f"Error analyzing file {file}: {str(e)}")
                            error_result = {
                                'filename': file,
                                'scan_result': {
                                    'status': 'error',
                                    'error': str(e),
                                    'malicious': 0,
                                    'undetected': 0,
                                    'risk_level': 'Unknown',
                                    'risk_score': 0
                                }
                            }
                            app.logger.info(f"Adding error result for {file}: {error_result}")
                            results.append(error_result)
            finally:
                app.logger.info("Cleaning up temp directory")
                shutil.rmtree(temp_dir)
                
        if not results:
            app.logger.warning("No results found in ZIP")
            return [{
                'filename': os.path.basename(file_path),
                'scan_result': {
                    'status': 'error',
                    'error': 'No files found in ZIP',
                    'malicious': 0,
                    'undetected': 0,
                    'risk_level': 'Unknown',
                    'risk_score': 0
                }
            }]
            
        app.logger.info(f"ZIP analysis complete. Results: {results}")
        return results
        
    except Exception as e:
        app.logger.error(f"ZIP analysis error: {str(e)}")
        return [{
            'filename': os.path.basename(file_path),
            'scan_result': {
                'status': 'error',
                'error': str(e),
                'malicious': 0,
                'undetected': 0,
                'risk_level': 'Unknown',
                'risk_score': 0
            }
        }]

def analyze_docx(file_path):
    """Analyze contents of a DOCX file"""
    try:
        app.logger.info(f"Starting DOCX analysis for: {file_path}")
        
        # Scan with VirusTotal
        scan_result = scan_file_with_virustotal(file_path, os.path.basename(file_path))
        
        if scan_result.get('error'):
            app.logger.error(f"Scan error: {scan_result['error']}")
            cleanup_file(file_path)
            return render_template('error.html', error=scan_result['error']), 500
        
        # Clean up file if not queued for analysis
        if scan_result.get('status') != 'queued':
            cleanup_file(file_path)
        
        response_data = {
            'filename': os.path.basename(file_path),
            'is_folder': False,
            'scan_result': scan_result,
            'status': scan_result.get('status', 'analyzed'),
            'risk_level': scan_result.get('risk_level', 'Unknown'),
            'score': float(scan_result.get('risk_score', 0))
        }
        
        app.logger.info(f"DOCX analysis complete: {response_data}")
        return render_template('result.html', **response_data)
            
    except Exception as e:
        error_msg = str(e)
        app.logger.error(f"DOCX analysis error: {error_msg}")
        if os.path.exists(file_path):
            cleanup_file(file_path)
        return render_template('error.html', error=error_msg), 500

def scan_file_with_virustotal(file_path, filename):
    """Scan a file with VirusTotal API"""
    try:
        app.logger.info(f"Scanning file: {filename}")
        
        # Calculate file hash
        with open(file_path, 'rb') as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()
            
        app.logger.info(f"File hash: {file_hash}")
        
        # First check if the file has been scanned before
        headers = {
            "accept": "application/json",
            "x-apikey": os.getenv('VIRUS_TOTAL_API_KEY')
        }
        
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            app.logger.info("Found existing scan results")
            data = response.json()
            
            # Ensure we have the required data
            if 'data' not in data or 'attributes' not in data['data']:
                app.logger.error("Invalid response format from VirusTotal")
                return {
                    'status': 'error',
                    'error': 'Invalid response from VirusTotal',
                    'malicious': 0,
                    'undetected': 0,
                    'risk_level': 'Unknown',
                    'risk_score': 0,
                    'detailed_results': {}
                }
                
            attributes = data['data']['attributes']
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            
            # Convert stats to integers
            malicious = int(last_analysis_stats.get('malicious', 0))
            undetected = int(last_analysis_stats.get('undetected', 0))
            total = malicious + undetected
            
            # Calculate risk score and level
            risk_score = round((malicious / total * 100) if total > 0 else 0, 2)
            risk_level = "Low" if risk_score < 33 else "Medium" if risk_score < 66 else "High"
            
            result = {
                'status': 'analyzed',
                'malicious': malicious,
                'undetected': undetected,
                'risk_level': risk_level,
                'risk_score': risk_score,
                'detailed_results': {}
            }
            
            app.logger.info(f"Scan result: {result}")
            return result
            
        elif response.status_code == 404:
            app.logger.info("File not previously scanned, uploading for analysis")
            
            # Get upload URL
            url = "https://www.virustotal.com/api/v3/files/upload_url"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                upload_url = response.json().get('data')
                
                if not upload_url:
                    app.logger.error("Failed to get upload URL")
                    return {
                        'status': 'error',
                        'error': 'Failed to get upload URL',
                        'malicious': 0,
                        'undetected': 0,
                        'risk_level': 'Unknown',
                        'risk_score': 0
                    }
                
                # Upload file
                files = {"file": (filename, open(file_path, "rb"))}
                response = requests.post(upload_url, files=files, headers=headers)
                
                if response.status_code == 200:
                    app.logger.info("File uploaded successfully")
                    return {
                        'status': 'queued',
                        'malicious': 0,
                        'undetected': 0,
                        'risk_level': 'Unknown',
                        'risk_score': 0
                    }
                else:
                    error_msg = f"Failed to upload file: {response.text}"
                    app.logger.error(error_msg)
                    return {
                        'status': 'error',
                        'error': error_msg,
                        'malicious': 0,
                        'undetected': 0,
                        'risk_level': 'Unknown',
                        'risk_score': 0
                    }
            else:
                error_msg = f"Failed to get upload URL: {response.text}"
                app.logger.error(error_msg)
                return {
                    'status': 'error',
                    'error': error_msg,
                    'malicious': 0,
                    'undetected': 0,
                    'risk_level': 'Unknown',
                    'risk_score': 0
                }
        else:
            error_msg = f"Failed to check file status: {response.text}"
            app.logger.error(error_msg)
            return {
                'status': 'error',
                'error': error_msg,
                'malicious': 0,
                'undetected': 0,
                'risk_level': 'Unknown',
                'risk_score': 0
            }
            
    except Exception as e:
        error_msg = str(e)
        app.logger.error(f"Error in scan_file_with_virustotal: {error_msg}")
        return {
            'status': 'error',
            'error': error_msg,
            'malicious': 0,
            'undetected': 0,
            'risk_level': 'Unknown',
            'risk_score': 0
        }

@app.route('/')
def index():
    # Renders the main page
    return render_template('index.html')

@app.route('/check_status/<filename>')
def check_status(filename):
    """Check the status of a file analysis"""
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
        
        # Get file hash
        file_hash = get_hash(file_path)
        if not file_hash:
            return jsonify({'error': "File not found"})

        # Check analysis status
        response = requests.get(
            f"{vt_config['base']}/files/{file_hash}",
            headers=vt_config['headers']
        )
        
        if response.status_code == 200:
            result = response.json()
            stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            
            if stats:
                # Analysis is complete, clean up the file
                cleanup_file(file_path)
                return jsonify({'status': 'completed'})
            
        return jsonify({'status': 'queued'})
        
    except Exception as e:
        app.logger.error(f"Status check error: {str(e)}")
        return jsonify({'error': str(e)})

@app.route('/check_zip_status/<filename>')
def check_zip_status(filename):
    """Check the status of a ZIP file analysis"""
    try:
        app.logger.info(f"Checking ZIP status for: {filename}")
        
        # Validate filename
        if not filename:
            app.logger.error("No filename provided")
            return jsonify({'error': "No filename provided"}), 400
            
        # Clean and validate filename
        filename = secure_filename(filename)
        if not filename:
            app.logger.error("Invalid filename")
            return jsonify({'error': "Invalid filename"}), 400
        
        temp_dir = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_extract')
        if not os.path.exists(temp_dir):
            app.logger.error(f"Temp directory not found: {temp_dir}")
            return jsonify({'error': "No analysis in progress", 'status': 'complete'}), 404
            
        results = []
        stats = {
            'total_files': 0,
            'analyzed': 0,
            'clean': 0,
            'malicious': 0,
            'suspicious': 0,
            'errors': 0,
            'queued': 0
        }
        
        try:
            # Count total files
            total_files = sum([len(files) for _, _, files in os.walk(temp_dir)])
            if total_files == 0:
                app.logger.error("No files found in temp directory")
                shutil.rmtree(temp_dir)
                return jsonify({'error': "No files found", 'status': 'complete'}), 404
                
            stats['total_files'] = total_files
            app.logger.info(f"Found {total_files} files to check")
            
        except Exception as e:
            app.logger.error(f"Error counting files: {str(e)}")
            return jsonify({'error': "Failed to count files"}), 500
        
        # Check each file's status
        for root, _, files in os.walk(temp_dir):
            for file in files:
                try:
                    file_path = os.path.join(root, file)
                    app.logger.info(f"Checking status for: {file}")
                    
                    # Get file hash
                    file_hash = get_hash(file_path)
                    if not file_hash:
                        app.logger.error(f"Failed to get hash for: {file}")
                        stats['errors'] += 1
                        results.append({
                            'name': file,
                            'status': 'error',
                            'error': 'Failed to get file hash'
                        })
                        continue
                    
                    # Check VirusTotal status
                    try:
                        response = requests.get(
                            f"{vt_config['base']}/files/{file_hash}",
                            headers=vt_config['headers']
                        )
                        
                        if response.status_code == 200:
                            result = response.json()
                            analysis_stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                            
                            if analysis_stats:
                                stats['analyzed'] += 1
                                malicious = analysis_stats.get('malicious', 0)
                                total_scans = sum(analysis_stats.values())
                                risk_score, risk_level = calc_score(malicious, total_scans)
                                
                                results.append({
                                    'name': file,
                                    'status': 'complete',
                                    'risk_level': risk_level,
                                    'risk_score': risk_score,
                                    'stats': analysis_stats
                                })
                            else:
                                stats['queued'] += 1
                                results.append({
                                    'name': file,
                                    'status': 'queued'
                                })
                        elif response.status_code == 404:
                            stats['queued'] += 1
                            results.append({
                                'name': file,
                                'status': 'queued'
                            })
                        else:
                            app.logger.error(f"VirusTotal API error for {file}: {response.status_code}")
                            stats['errors'] += 1
                            results.append({
                                'name': file,
                                'status': 'error',
                                'error': f"API error: {response.status_code}"
                            })
                            
                    except requests.exceptions.RequestException as e:
                        app.logger.error(f"Request error for {file}: {str(e)}")
                        stats['errors'] += 1
                        results.append({
                            'name': file,
                            'status': 'error',
                            'error': f"Request failed: {str(e)}"
                        })
                        
                except Exception as e:
                    app.logger.error(f"Error processing {file}: {str(e)}")
                    stats['errors'] += 1
                    results.append({
                        'name': file,
                        'status': 'error',
                        'error': str(e)
                    })
        
        # Clean up if all files are analyzed or only errors remain
        remaining = stats['queued']
        if remaining == 0:
            app.logger.info("All files processed, cleaning up")
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                
        response_data = {
            'status': 'complete' if remaining == 0 else 'in_progress',
            'completed': remaining == 0,
            'analyzed': stats['analyzed'],
            'total': stats['total_files'],
            'remaining': remaining,
            'stats': stats,
            'files': results
        }
        
        app.logger.info(f"Status check complete: {response_data['status']}")
        return jsonify(response_data)
        
    except Exception as e:
        app.logger.error(f"ZIP status check error: {str(e)}")
        # Clean up on critical error
        if 'temp_dir' in locals() and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
        return jsonify({'error': str(e), 'status': 'error'}), 500

@app.route('/analyze', methods=['POST'])
def analyze_file():
    """Handle file upload and analysis"""
    if 'file' not in request.files:
        return render_template('error.html', error="No file provided"), 400

    file = request.files['file']
    if file.filename == '':
        return render_template('error.html', error="No selected file"), 400

    try:
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            filename = secure_filename(file.filename)
            file.save(temp_file.name)
            filepath = temp_file.name
            
            # Process the file
            app.logger.info(f"Processing file: {filename}")
            scan_result = scan_file_with_virustotal(filepath, filename)
            
            # Always delete the temporary file after scanning
            try:
                os.unlink(filepath)
                app.logger.info(f"Successfully deleted temporary file: {filepath}")
            except Exception as e:
                app.logger.error(f"Error deleting temporary file {filepath}: {str(e)}")
            
            if scan_result.get('error'):
                app.logger.error(f"Scan error: {scan_result['error']}")
                return render_template('error.html', error=scan_result['error']), 500
            
            response_data = {
                'filename': filename,
                'is_folder': False,
                'scan_result': scan_result,
                'status': scan_result.get('status', 'analyzed'),
                'risk_level': scan_result.get('risk_level', 'Unknown'),
                'score': float(scan_result.get('risk_score', 0))
            }
            
            app.logger.info(f"Analysis complete for {filename}: {response_data}")
            return render_template('result.html', **response_data)
                
    except Exception as e:
        error_msg = str(e)
        app.logger.error(f"Analysis error: {error_msg}")
        # Ensure file is deleted even if an error occurs
        if 'filepath' in locals() and os.path.exists(filepath):
            try:
                os.unlink(filepath)
            except:
                pass
        return render_template('error.html', error=error_msg), 500

@app.route('/test_analyze')
def test_analyze():
    """Test route to analyze ChristianTurcuNCI.docx"""
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'ChristianTurcuNCI.docx')
    if not os.path.exists(filepath):
        return jsonify({"error": "Test file not found"}), 404
        
    result = scan_file_with_virustotal(filepath, 'ChristianTurcuNCI.docx')
    return jsonify(result)

def cleanup_file(filepath):
    """Safely clean up a file"""
    try:
        if os.path.exists(filepath):
            os.remove(filepath)
            app.logger.info(f"Cleaned up file: {filepath}")
    except Exception as e:
        app.logger.error(f"Error cleaning up file {filepath}: {str(e)}")

def cleanup_directory(dirpath):
    """Safely clean up a directory and its contents"""
    try:
        if os.path.exists(dirpath):
            # Try to remove read-only flag from all files
            for root, dirs, files in os.walk(dirpath):
                for d in dirs:
                    try:
                        path = os.path.join(root, d)
                        os.chmod(path, 0o777)
                    except:
                        pass
                for f in files:
                    try:
                        path = os.path.join(root, f)
                        os.chmod(path, 0o777)
                    except:
                        pass
            
            # Try to remove the directory
            try:
                shutil.rmtree(dirpath)
                app.logger.info(f"Cleaned up directory: {dirpath}")
            except Exception as e:
                app.logger.error(f"Failed to remove directory {dirpath}: {str(e)}")
                
                # If rmtree fails, try to remove files one by one
                for root, dirs, files in os.walk(dirpath, topdown=False):
                    for name in files:
                        try:
                            os.remove(os.path.join(root, name))
                        except:
                            pass
                    for name in dirs:
                        try:
                            os.rmdir(os.path.join(root, name))
                        except:
                            pass
                try:
                    os.rmdir(dirpath)
                except:
                    pass
    except Exception as e:
        app.logger.error(f"Error cleaning up directory {dirpath}: {str(e)}")

class FileTooBigError(Exception):
    """Custom exception for file size limit"""
    pass

def save_file_safely(file, filename):
    """Save file with size check"""
    try:
        # Read file in chunks to check size
        total_size = 0
        chunk_size = 8192  # 8KB chunks
        chunks = []

        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            total_size += len(chunk)
            if total_size > app.config['MAX_CONTENT_LENGTH']:
                raise FileTooBigError("File too large")
            chunks.append(chunk)

        # Reset the file pointer
        file.seek(0)

        # If the file gets until here the size is OK
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'wb') as f:
            for chunk in chunks:
                f.write(chunk)
        return filepath
    except FileTooBigError:
        raise
    except Exception as e:
        app.logger.error(f"Error saving file: {str(e)}")
        raise

if __name__ == '__main__':
    app.run(debug=True)
