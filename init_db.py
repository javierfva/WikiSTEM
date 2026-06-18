# WikiSTEM | Javier Fernando Vega Alamo | CS50x 2026
# This file was drafted with assistance from Claude (Anthropic) inside
# Google Antigravity, working from a specification I authored. All
# architectural decisions, security choices, and final logic were
# reviewed and verified by me before commit.
#
# Run once to initialise the database:
#   python init_db.py
#
# BEFORE RUNNING: copy .env.example to .env and fill in all values.
# ADMIN SEED: change ADMIN_USERNAME / ADMIN_EMAIL / ADMIN_PASSWORD below.

import os
from dotenv import load_dotenv

load_dotenv()

# ── Admin seed credentials ─────────────────────────────────────────────────────
# SECURITY (audit finding S4): never bake an admin password into tracked source — a
# forgotten default is a guaranteed-known credential on the most-attacked account.
# These come from the environment (.env); ADMIN_PASSWORD has no default, so seeding
# refuses to run unless you set one (8-128 chars). Username/email fall back to
# sensible defaults only.
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_EMAIL    = os.environ.get('ADMIN_EMAIL', 'admin@wikistem.edu.pe')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', '')
# ──────────────────────────────────────────────────────────────────────────────

from config import get_config
from flask import Flask
from models import db, User
from helpers import encrypt, email_hash
from sqlalchemy import text


def create_app():
    app = Flask(__name__)
    app.config.from_object(get_config())
    db.init_app(app)
    return app


def create_fts_table(app):
    """Create the FTS5 virtual table and sync triggers (§12)."""
    with app.app_context():
        with db.engine.connect() as conn:
            conn.execute(db.text("""
                CREATE VIRTUAL TABLE IF NOT EXISTS submissions_fts USING fts5(
                    title,
                    description_md,
                    tags,
                    content='submissions',
                    content_rowid='id'
                )
            """))
            conn.execute(db.text("""
                CREATE TRIGGER IF NOT EXISTS submissions_ai
                AFTER INSERT ON submissions BEGIN
                    INSERT INTO submissions_fts(rowid, title, description_md, tags)
                    VALUES (new.id, new.title, new.description_md, new.tags);
                END
            """))
            conn.execute(db.text("""
                CREATE TRIGGER IF NOT EXISTS submissions_ad
                AFTER DELETE ON submissions BEGIN
                    INSERT INTO submissions_fts(submissions_fts, rowid, title, description_md, tags)
                    VALUES ('delete', old.id, old.title, old.description_md, old.tags);
                END
            """))
            # UPDATE trigger: without it, editing a submission's title,
            # description_md, or tags leaves the FTS index stale (search would
            # still match the OLD text). The 'delete' row removes the old index
            # entry before the new one is inserted.
            conn.execute(db.text("""
                CREATE TRIGGER IF NOT EXISTS submissions_au
                AFTER UPDATE ON submissions BEGIN
                    INSERT INTO submissions_fts(submissions_fts, rowid, title, description_md, tags)
                    VALUES ('delete', old.id, old.title, old.description_md, old.tags);
                    INSERT INTO submissions_fts(rowid, title, description_md, tags)
                    VALUES (new.id, new.title, new.description_md, new.tags);
                END
            """))
            conn.commit()
    print('  FTS5 table + triggers: OK')


def create_upload_dirs(app):
    """Create upload subdirectories (§24, step 3 / §4.9 M1)."""
    with app.app_context():
        upload_folder = app.config['UPLOAD_FOLDER']
        # Static uploads — served directly by Flask
        for sub in ('covers', 'extras', 'papers', 'avatars'):
            path = os.path.join(upload_folder, sub)
            os.makedirs(path, exist_ok=True)
            print(f'  {path}: OK')

        # Documents live OUTSIDE static/ so they can never be served inline.
        # Served only via the hardened download_document route (§4.9 M1).
        doc_path = os.path.join(app.instance_path, 'uploads', 'documents')
        os.makedirs(doc_path, exist_ok=True)
        print(f'  {doc_path}: OK')


def migrate_users_columns(app):
    """Add admin-hardening columns to an EXISTING users table if missing.

    The project uses db.create_all() (no Alembic), which never ALTERs an existing
    table. On a fresh DB create_all already added these, so this is a no-op; on an
    upgraded DB it adds each missing column without wiping data. Idempotent.
    """
    with app.app_context():
        cols = {row[1] for row in db.session.execute(
            text('PRAGMA table_info(users)')).fetchall()}
        # (column name, ALTER statement) — failed_totp_count / totp_locked_until back
        # the per-account TOTP brute-force lockout (audit MEDIUM); totp_secret is the
        # original 2FA column. SQLite only allows one ADD COLUMN per statement.
        for name, ddl in (
            ('totp_secret',       'ALTER TABLE users ADD COLUMN totp_secret TEXT'),
            ('failed_totp_count', 'ALTER TABLE users ADD COLUMN failed_totp_count INTEGER NOT NULL DEFAULT 0'),
            ('totp_locked_until', 'ALTER TABLE users ADD COLUMN totp_locked_until DATETIME'),
        ):
            if name not in cols:
                db.session.execute(text(ddl))
                db.session.commit()
                print(f'  users.{name} column: ADDED')
            else:
                print(f'  users.{name} column: OK')


def migrate_submissions_columns(app):
    """Add the denormalised like_count column to an EXISTING submissions table.

    Mirrors migrate_users_columns (db.create_all never ALTERs an existing table). On a
    fresh DB create_all already added like_count, so the ADD is skipped; on an upgraded
    DB it adds the column and BACKFILLS it from the real like totals so existing rows
    don't render 0. Idempotent: re-runs only re-sync the backfill. (audit finding P1)
    """
    with app.app_context():
        cols = {row[1] for row in db.session.execute(
            text('PRAGMA table_info(submissions)')).fetchall()}
        if 'like_count' not in cols:
            db.session.execute(text(
                'ALTER TABLE submissions ADD COLUMN like_count INTEGER NOT NULL DEFAULT 0'))
            db.session.commit()
            print('  submissions.like_count column: ADDED')
        else:
            print('  submissions.like_count column: OK')
        # Backfill / re-sync from the authoritative like rows.
        db.session.execute(text("""
            UPDATE submissions SET like_count = (
                SELECT COUNT(*) FROM submission_likes
                WHERE submission_likes.submission_id = submissions.id
            )
        """))
        db.session.commit()
        print('  submissions.like_count: backfilled from submission_likes')


def seed_admin(app):
    """Insert the admin user if one does not already exist."""
    with app.app_context():
        # SECURITY (audit finding S4): refuse to seed with no password rather than
        # falling back to a baked-in default.
        if not ADMIN_PASSWORD or len(ADMIN_PASSWORD) < 8:
            print('  ADMIN_PASSWORD not set (or < 8 chars) — skipping admin seed. '
                  'Set ADMIN_PASSWORD in .env and re-run to create the admin.')
            return

        existing = User.query.filter_by(
            email_hash=email_hash(ADMIN_EMAIL)
        ).first()
        if existing:
            print(f'  Admin already exists: {existing.username} — skipping seed.')
            return

        admin = User(
            username      = ADMIN_USERNAME,
            email         = encrypt(ADMIN_EMAIL),
            email_hash    = email_hash(ADMIN_EMAIL),
            school        = 'Other',
            grade         = 'Universidad',
            role          = 'admin',
            is_banned     = False,
            bio_public    = False,
        )
        admin.set_password(ADMIN_PASSWORD)
        db.session.add(admin)
        db.session.commit()
        print(f'  Admin seeded: {ADMIN_USERNAME} ({ADMIN_EMAIL})')


def main():
    print('WikiSTEM — initialising database...')
    app = create_app()

    with app.app_context():
        db.create_all()
        print('  db.create_all(): OK')

    create_fts_table(app)
    create_upload_dirs(app)
    migrate_users_columns(app)
    migrate_submissions_columns(app)
    seed_admin(app)

    print('\nDone. Run `flask run` to start the development server.')
    print('REMINDER: Change the admin password in .env / ADMIN_PASSWORD before deploying.')


if __name__ == '__main__':
    main()
