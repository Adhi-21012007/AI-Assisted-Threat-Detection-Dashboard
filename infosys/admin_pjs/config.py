import os
BASE_DIR=os.path.abspath(os.path.dirname(__file__))
PROJECT_ROOT=os.path.dirname(BASE_DIR)
class Config:
    ENVIRONMENT=os.environ.get('APP_ENV','development')
    SECRET_KEY=os.environ.get('SECRET_KEY','admin-portal-dev-secret')
    DATABASE=os.environ.get('COMPANY_DATABASE_PATH',os.path.join(PROJECT_ROOT,'company.db'))
    UPLOAD_FOLDER=os.environ.get('UPLOAD_FOLDER',os.path.join(PROJECT_ROOT,'shared_uploads'))
    SESSION_COOKIE_HTTPONLY=True
    SESSION_COOKIE_SAMESITE='Lax'
    SESSION_COOKIE_SECURE=ENVIRONMENT=='production'
