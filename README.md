# Advanced API Threat Intelligence Platform (APITIPM)

A web-based application that analyzes files for potential security threats using the VirusTotal API.

## Live Demo
The application is deployed and accessible at: https://advanced-api-project.onrender.com

## Features
- File upload and analysis
- Integration with VirusTotal API
- Support for multiple file types including ZIP files
- Real-time analysis status updates
- Detailed threat analysis reports
- Modern and user-friendly interface

## Technologies Used
- Python/Flask
- JavaScript
- HTML/CSS
- VirusTotal API
- Render (Deployment Platform)

## Local Development Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/Christian-Turcu/AdvancedAPIProject.git
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up environment variables:
   Create a `.env` file with your VirusTotal API key:
   ```
   VIRUS_TOTAL_API_KEY=your_api_key_here
   ```

4. Run the application:
   ```bash
   python app.py
   ```

## API Documentation
The application uses the VirusTotal API v3 for file analysis. For more information, visit [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview).

## License
This project is licensed under the MIT License - see the LICENSE file for details.
