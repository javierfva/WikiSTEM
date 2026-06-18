# WikiSTEM | Javier Fernando Vega Alamo | CS50x 2026
# This file was drafted with assistance from Claude (Anthropic) inside
# Google Antigravity, working from a specification I authored. All
# architectural decisions, security choices, and final logic were
# reviewed and verified by me before commit.

import os
from datetime import timedelta


class BaseConfig:
    SECRET_KEY                    = os.environ['SECRET_KEY']
    SQLALCHEMY_DATABASE_URI       = 'sqlite:///wikistem.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    WTF_CSRF_ENABLED              = True
    WTF_CSRF_TIME_LIMIT           = 3600          # 1 hour
    # audit finding B1: the request-body cap must exceed the SUM of the per-file
    # upload limits (helpers.py: 20 MB/doc, 5 MB/img), not a single file. At 25 MB a
    # lone 20 MB PDF + cover already 413'd before the handler ran. 70 MB covers a
    # realistic research submission (main PDF + 1-2 extra PDFs + cover) while still
    # bounding a malicious oversize body. A friendly 413 handler (app.py) explains
    # the limit instead of a bare Werkzeug error.
    MAX_CONTENT_LENGTH            = 70 * 1024**2  # 70 MB request body cap
    PERMANENT_SESSION_LIFETIME    = timedelta(days=14)
    # Admin hardening (owner-approved, beyond v4 spec): the admin SESSION is made
    # non-persistent in code (login_user(remember=False) + session.permanent=False),
    # so it dies on browser close. PERMANENT_SESSION_LIFETIME above governs students.
    UPLOAD_FOLDER                 = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'static', 'uploads'
    )
    # User-uploaded DOCUMENTS live OUTSIDE static/ (see §4.9 M1) so they can
    # never be served inline. Both the save path (submit routes), the serve
    # path (download_document), and the cleanup path (_delete_file_if_exists)
    # must use this same directory. It is created by init_db.py.
    #   document dir = <instance_path>/uploads/documents
    # (instance_path is resolved at runtime via current_app.instance_path)


class DevConfig(BaseConfig):
    APP_ENV               = 'development'
    DEBUG                 = True
    TESTING               = False
    SESSION_COOKIE_SECURE = False


class ProdConfig(BaseConfig):
    APP_ENV               = 'production'
    DEBUG                 = False
    TESTING               = False
    SESSION_COOKIE_SECURE = True
    PREFERRED_URL_SCHEME  = 'https'


def get_config():
    # v4 — APP_ENV replaces deprecated FLASK_ENV. We read our own variable
    # so we are not at the mercy of Flask's internal handling of FLASK_ENV.
    # The chosen config object also CARRIES app_env as a config value
    # (app.config['APP_ENV']) so runtime guards — ProxyFix (§4.9 G4),
    # Talisman (§4.5), and the Limiter — can branch on it consistently.
    env = os.environ.get('APP_ENV', 'development').lower()
    return ProdConfig if env == 'production' else DevConfig
