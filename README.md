# 🔐 Secure Geo-Data Sharing System

A secure REST API using Flask to allow encrypted, role-based access to geospatial data.

## Features
- AES encryption for geo-data using Fernet
- JWT authentication for secure sessions
- Role-Based Access Control (RBAC)
- SQLite-backed storage of encrypted data

## Setup Instructions

```bash
pip install -r requirements.txt
python app.py
```

## API Endpoints
- POST /register
- POST /login
- POST /upload
- GET /retrieve
