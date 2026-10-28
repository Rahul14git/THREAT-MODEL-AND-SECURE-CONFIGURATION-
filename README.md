
# Secure Authentication Lab

## Overview
A beginner-friendly authentication service built with Python and Flask.

## Security Features
- Password hashing using Werkzeug
- Username and password validation
- Login and registration rate limiting
- CSRF protection for form submissions
- HTTP-only session cookies
- Parameterized SQLite queries
- Login-required dashboard and logout

## Technologies
- Python
- Flask
- SQLite
- Flask-WTF
- Flask-Limiter

## Run Locally
1. Install Python 3.10 or newer.
2. Install dependencies:

   pip install -r requirements.txt

3. Start the application:

   python app.py

4. Open http://127.0.0.1:5000/login in your browser.

## Security Notes
This project is an educational demonstration, not a production-ready
authentication system. Production deployment requires a stable secret
key, HTTPS, persistent rate limiting, and additional security testing.
