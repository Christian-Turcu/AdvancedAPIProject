# Automated script when I ranned the run_app.bat command.
# This line of code prevents commands from being displayed in the console when they run.

# Runs the Flask application in a seprate window.

@echo off
powershell -Command "Start-Process cmd -Verb RunAs -ArgumentList '/c cd %~dp0 && python app.py'"
