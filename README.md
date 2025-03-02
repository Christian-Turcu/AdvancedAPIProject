Advanced API Threat Intelligence Platform APITIPM

This is my web-based application that analyzes files for malicious file/folder threats using the VirusTotal API.

My Website is up and running with the free version of onrender which you will need to run it by yourself.
https://advanced-api-project.onrender.com

Features of my Advanced API
- File upload and analysis
- Integration with VirusTotal API
- Support for multiple file types including ZIP files
- Real-time analysis status updates
- Detailed threat analysis reports
- Modern and user-friendly interface

Technologies Used for my Advanced API
- Python/Flask
- JavaScript
- HTML/CSS
- VirusTotal API
- Render (Deployment Platform)

If you want to set this up and locally deploy from your host, please follow these steps:
1. Clone the repository like this:
   
   git clone https://github.com/Christian-Turcu/AdvancedAPIProject.git
   

2. Install dependencies:
  
   pip install -r requirements.txt
   
This will Install all the plug-ins that you will need to run and start the prototype.

3. Set up environment variables:
  You will need to Create a .env file with your VirusTotal API key:
   
   VIRUS_TOTAL_API_KEY = your Key goes in here
   
The way to get this key is you go to this website link: https://www.virustotal.com/gui/home/upload and Sign in then click on your profile to get the API KEY.

4. After that is done and set up Run the application:

   python app.py


API Documentation
My application uses the VirusTotal API v3 for file analysis. [VirusTotal API Documentation](https://developers.virustotal.com/reference/overview).
