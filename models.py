# WikiSTEM | Javier Fernando Vega Alamo | CS50x 2026
# This file was drafted with assistance from Claude (Anthropic) inside
# Google Antigravity, working from a specification I authored. All
# architectural decisions, security choices, and final logic were
# reviewed and verified by me before commit.

import json
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import event
from sqlalchemy.engine import Engine

db = SQLAlchemy()


# Listen on the Engine CLASS, not db.engine. In Flask-SQLAlchemy 3.x db.engine
# requires an active app context, so evaluating it here at import time (before
# db.init_app) would raise. Targeting Engine attaches to every connection the
# app opens and needs no context.
@event.listens_for(Engine, 'connect')
def _fk_pragma(dbapi_connection, _):
    cursor = dbapi_connection.cursor()
    cursor.execute('PRAGMA foreign_keys=ON')
    # PERF (audit finding P3): WAL lets readers and a writer proceed concurrently
    # instead of the default rollback journal, where a single writer blocks every
    # reader. The detail-page view counter writes on navigation, so without WAL the
    # site serialises under load. synchronous=NORMAL is the safe WAL companion
    # (durable across app crashes; only a power-loss at the wrong instant risks the
    # last commit — acceptable for this workload). Both PRAGMAs are idempotent.
    cursor.execute('PRAGMA journal_mode=WAL')
    cursor.execute('PRAGMA synchronous=NORMAL')
    cursor.close()


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id               = db.Column(db.Integer, primary_key=True)
    username         = db.Column(db.String(32), unique=True, nullable=False)
    email            = db.Column(db.Text, nullable=False)           # Fernet-encrypted
    email_hash       = db.Column(db.String(64), unique=True, nullable=False)  # SHA-256
    password_hash    = db.Column(db.String(256), nullable=False)
    school           = db.Column(db.String(64))
    grade            = db.Column(db.String(32))
    role             = db.Column(db.String(16), nullable=False, default='student')
    is_banned        = db.Column(db.Boolean, nullable=False, default=False)
    bio              = db.Column(db.Text)                           # Fernet-encrypted
    bio_public       = db.Column(db.Boolean, nullable=False, default=True)
    avatar_filename  = db.Column(db.String(64))
    skills_tags      = db.Column(db.Text)
    linkedin_url     = db.Column(db.Text)
    github_url       = db.Column(db.Text)
    created_at       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    last_login       = db.Column(db.DateTime)
    # Admin hardening (owner-approved, beyond v4 spec): Fernet-encrypted base32 TOTP
    # secret for admin two-factor auth. NULL until the admin enrolls via /admin/2fa/setup.
    # Stored encrypted exactly like `email`/`bio` (helpers.encrypt/decrypt). Admin-only.
    totp_secret      = db.Column(db.Text)
    # Per-account TOTP brute-force lockout (audit MEDIUM): count consecutive failed
    # admin TOTP codes; freeze the account when it crosses TOTP_MAX_FAILS so a
    # distributed attacker can't bypass the per-IP rate limit. Reset on any success.
    failed_totp_count = db.Column(db.Integer, nullable=False, default=0)
    totp_locked_until = db.Column(db.DateTime)   # UTC instant; NULL when not locked

    submissions      = db.relationship('Submission', backref='author',
                                       cascade='all, delete-orphan', lazy='dynamic')
    likes            = db.relationship('SubmissionLike', backref='user',
                                       cascade='all, delete-orphan', lazy='dynamic')
    view_history     = db.relationship('ViewHistory', backref='user',
                                       cascade='all, delete-orphan', lazy='dynamic')

    def set_password(self, plain):
        # SECURITY: pin PBKDF2 explicitly. Werkzeug 3.x changed the default of
        # generate_password_hash() to scrypt, but the spec (§4.1) and CLAUDE.md
        # mandate "PBKDF2 only". The login route's constant-time DUMMY_HASH must
        # use this exact same method or the timing defence (§4.1) breaks.
        # Stored format: pbkdf2:sha256:<iterations>$<random_salt>$<hash>
        self.password_hash = generate_password_hash(plain, method='pbkdf2:sha256')

    def check_password(self, plain):
        return check_password_hash(self.password_hash, plain)


class Submission(db.Model):
    __tablename__ = 'submissions'

    id               = db.Column(db.Integer, primary_key=True)
    track            = db.Column(db.String(16), nullable=False)    # 'research' | 'project'
    title            = db.Column(db.String(120), nullable=False)
    slug             = db.Column(db.String(100), unique=True, nullable=False)
    author_id        = db.Column(db.Integer,
                                 db.ForeignKey('users.id', ondelete='CASCADE'),
                                 nullable=False)
    # pending | approved | rejected | flagged | banned_hidden
    status           = db.Column(db.String(20), nullable=False, default='pending')
    created_at       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    # audit finding B3: give updated_at a creation default so never-updated rows are
    # not NULL (admin queues and any updated_at ordering then behave consistently).
    # onupdate still refreshes it on every later mutation.
    updated_at       = db.Column(db.DateTime,
                                 default=lambda: datetime.now(timezone.utc),
                                 onupdate=lambda: datetime.now(timezone.utc))
    views            = db.Column(db.Integer, nullable=False, default=0)
    # PERF (audit finding P1): denormalised like total so card/list rendering reads a
    # column instead of firing a COUNT(*) per card (N+1). Maintained atomically in the
    # `like` route on every like/unlike; backfilled for existing DBs by init_db.
    like_count       = db.Column(db.Integer, nullable=False, default=0)

    # Shared fields
    description_md   = db.Column(db.Text)
    description_html = db.Column(db.Text)
    category         = db.Column(db.String(80))
    tags             = db.Column(db.String(160))
    cover_image      = db.Column(db.String(64))
    external_link    = db.Column(db.Text)
    ai_report        = db.Column(db.Text)    # JSON string
    ai_reviewed_at   = db.Column(db.DateTime)
    mod_report       = db.Column(db.Text)    # JSON string
    mod_reviewed_at  = db.Column(db.DateTime)
    mod_flag_reason  = db.Column(db.Text)

    # Research-only
    ib_type          = db.Column(db.String(40))   # Spanish label, e.g. 'Monografía (EE)'
    ib_subject       = db.Column(db.String(60))
    word_count       = db.Column(db.Integer)
    academic_year    = db.Column(db.String(4))
    main_pdf         = db.Column(db.String(64))
    extra_pdfs       = db.Column(db.Text)         # comma-separated filenames

    # Projects-only
    project_type     = db.Column(db.String(40))   # Spanish label, e.g. 'Arduino / Hardware'
    extra_images     = db.Column(db.Text)          # comma-separated filenames
    documents        = db.Column(db.Text)          # JSON: [{filename, original_name, size_kb, type}]
    code_snippet     = db.Column(db.Text)

    @property
    def documents_list(self):
        # Template-facing accessor. Always returns a list of dicts; never raises
        # into Jinja. Mirrors the json.loads(submission.documents) pattern used
        # by download_document / delete routes in app.py.
        if not self.documents:
            return []
        try:
            return json.loads(self.documents)
        except (ValueError, TypeError):
            return []

    likes            = db.relationship('SubmissionLike', backref='submission',
                                       cascade='all, delete-orphan', lazy='dynamic')
    view_records     = db.relationship('ViewHistory', backref='submission',
                                       cascade='all, delete-orphan', lazy='dynamic')
    moderation_logs  = db.relationship('ModerationLog', backref='submission',
                                       cascade='all, delete-orphan', lazy='dynamic')


class SubmissionLike(db.Model):
    __tablename__ = 'submission_likes'

    user_id          = db.Column(db.Integer,
                                 db.ForeignKey('users.id', ondelete='CASCADE'),
                                 primary_key=True)
    submission_id    = db.Column(db.Integer,
                                 db.ForeignKey('submissions.id', ondelete='CASCADE'),
                                 primary_key=True)
    created_at       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class ViewHistory(db.Model):
    __tablename__ = 'view_history'

    user_id          = db.Column(db.Integer,
                                 db.ForeignKey('users.id', ondelete='CASCADE'),
                                 primary_key=True)
    submission_id    = db.Column(db.Integer,
                                 db.ForeignKey('submissions.id', ondelete='CASCADE'),
                                 primary_key=True)
    viewed_at        = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        db.UniqueConstraint('user_id', 'submission_id', name='uq_view_history'),
    )


class ModerationLog(db.Model):
    __tablename__ = 'moderation_log'

    id               = db.Column(db.Integer, primary_key=True)
    submission_id    = db.Column(db.Integer,
                                 db.ForeignKey('submissions.id', ondelete='CASCADE'),
                                 nullable=False)
    # ai_flagged | ai_approved | ai_timeout | human_approved | human_rejected |
    # human_override | human_remoderate | human_rereview
    action           = db.Column(db.String(32), nullable=False)
    actor            = db.Column(db.String(64), nullable=False)   # 'system' or username
    note             = db.Column(db.Text)
    created_at       = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
