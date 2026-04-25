# ISP MTAANI

Flask-based internet management system with MikroTik router verification.

## Quick start

1. Install dependencies:
   - `python -m venv .venv`
   - `.\.venv\Scripts\activate`
   - `pip install -r requirements.txt`
2. Set environment variables:
   - `MIKROTIK_CRED_KEY` (required, 32 url-safe base64)
   - `DB_HOST`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `DB_PORT` (optional)
3. Run the app:
   - `python app.py`

Visit `http://localhost:5000/mikrotik`.


