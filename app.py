# WikiSTEM | Javier Fernando Vega Alamo | CS50x 2026
# This file was drafted with assistance from Claude (Anthropic) inside
# Google Antigravity, working from a specification I authored. All
# architectural decisions, security choices, and final logic were
# reviewed and verified by me before commit.

# ---------------------------------------------------------------------------
# Environment first. config.BaseConfig reads os.environ['SECRET_KEY'] at import
# time, so the .env MUST be loaded before `from config import get_config`.
# ---------------------------------------------------------------------------
from dotenv import load_dotenv
load_dotenv()

import os
import json
import re
import uuid
import base64
from io import BytesIO
from math import ceil
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, unquote, urljoin

import pyotp
import qrcode
from qrcode.image.pil import PilImage

from flask import (Flask, render_template, redirect, url_for, flash,
                   request, session, current_app, abort, jsonify,
                   send_from_directory)
from flask_login import (LoginManager, login_user, logout_user,
                         login_required, current_user)
from flask_wtf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import func
from sqlalchemy.orm import joinedload
from sqlalchemy.exc import IntegrityError, InvalidRequestError
from sqlalchemy.orm.exc import StaleDataError

from config import get_config
from models import (db, User, Submission, ViewHistory, SubmissionLike,
                    ModerationLog)
from forms import (LoginForm, RegistrationForm, LogoutForm,
                   ResearchSubmitForm, ProjectSubmitForm, RejectForm,
                   ProfileEditForm, DeleteSubmissionForm, TwoFactorForm,
                   SCHOOL_CHOICES, SCHOOL_OTHER_SENTINEL)
from helpers import (email_hash, encrypt, decrypt, render_markdown,
                     make_unique_slug, _try_commit_submission_with_slug,
                     sanitize_tags, secure_image_upload, secure_doc_upload,
                     _delete_file_if_exists, sanitise_fts_query, fuzzy_search,
                     totp_provisioning_uri, totp_verify,
                     make_pending_registration_token,
                     read_pending_registration_token, send_verification_email)
from ai_review import run_ai_moderation, run_ai_review
from recommendations import recommend_split_for_user, recommend_split_for_guest
from pixel_glyphs import (pixel_wordmark_pixels, pixel_text_pixels,
                          pixel_text_width, pixel_text_height)

# ---------------------------------------------------------------------------
# App + extension setup (§4)
# The FK PRAGMA listener is registered in models.py on the Engine class — it
# is NOT duplicated here.
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config.from_object(get_config())

# SECURITY (audit finding G4 — IP spoofing / rate-limit bypass in dev):
# ProxyFix blindly trusts X-Forwarded-For. That is correct behind the
# PythonAnywhere proxy in production, but in local development there is NO
# trusted proxy — so any client could send a forged X-Forwarded-For to spoof
# its IP and dodge Flask-Limiter. Only enable ProxyFix when a real proxy is
# in front of us. (§4.9 H2)
if app.config.get('APP_ENV') == 'production':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

db.init_app(app)

# SECURITY (audit finding H1): global CSRF protection so the AJAX like endpoint
# (which uses no FlaskForm) is covered via the X-CSRFToken header the frontend
# sends. Per-form tokens alone would leave that route CSRF-open.
csrf = CSRFProtect(app)

# Rate limiting (§4.4). memory:// is per-process and resets on restart — fine
# for the single-worker PythonAnywhere free tier (§4.9 M3).
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=['200 per hour'],
    storage_uri='memory://',
)

# Security headers (§4.5). Talisman is intentionally OFF in dev because it would
# force HTTPS and break localhost. DevConfig.DEBUG is True; ProdConfig.DEBUG is
# False, so this branch activates only in production.
CSP = {
    'default-src': "'self'",
    'style-src':   ["'self'", "'unsafe-inline'",
                    'https://cdn.jsdelivr.net',
                    'https://fonts.googleapis.com'],
    'font-src':    ["'self'", 'https://fonts.gstatic.com'],
    'script-src':  ["'self'", 'https://cdn.jsdelivr.net'],
    'img-src':     ["'self'", 'data:'],
    'frame-src':   ["'self'"],
    'frame-ancestors': "'none'",
}

if not app.config['DEBUG']:
    Talisman(
        app,
        content_security_policy=CSP,
        force_https=True,
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        session_cookie_secure=True,
        session_cookie_http_only=True,
        session_cookie_samesite='Lax',
    )

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Inicia sesión para continuar.'
login_manager.login_message_category = 'info'

# Build marker (owner-approved hardening): printed once at import. If you do NOT see
# this line in the server console, you are running STALE code — restart the server
# (and never launch dev with --no-reload, which freezes the code in memory).
app.logger.warning('WikiSTEM build: admin-2FA + 2FA-session-gate active')

# Constant for fake hash comparison — generated once at app startup so the login
# route can run a real PBKDF2 check even for unknown emails (§4.1).
# SECURITY: method is pinned to 'pbkdf2:sha256' to match models.User.set_password.
# Werkzeug 3.x defaults generate_password_hash() to scrypt, but the spec (§4.1)
# and CLAUDE.md mandate "PBKDF2 only". The dummy hash MUST use the same algorithm
# as real password hashes, otherwise the constant-time check has a different
# timing profile for unknown vs known emails and the enumeration defence breaks.
DUMMY_HASH = generate_password_hash('not-a-real-password-just-padding',
                                    method='pbkdf2:sha256')

# ---------------------------------------------------------------------------
# Login manager hooks (§4.9 H4 / G2.2)
# ---------------------------------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    user = db.session.get(User, int(user_id))
    # SECURITY (G2.2): a ban must take effect immediately, not at next login.
    # Returning None here makes Flask-Login treat the request as anonymous;
    # the @app.before_request hook below also tears down the stale session so
    # the banned user is cleanly logged out rather than silently de-authed.
    if user is None or user.is_banned:
        return None
    return user


@app.before_request
def _enforce_active_ban():
    # If a user was banned mid-session, current_user resolves to Anonymous
    # (because load_user returned None). Clear any residual session so the
    # logout is explicit and the next page shows the logged-out nav.
    if request.endpoint not in ('static', 'login', 'logout') \
       and current_user.is_authenticated is False \
       and session.get('_user_id') is not None:
        session.clear()


@app.before_request
def _require_admin_2fa():
    # ADMIN HARDENING (owner-approved, beyond v4 spec): 2FA must hold for the LIFE of
    # the session, not just at the login instant. An authenticated admin session is
    # only trusted if it carries the admin_2fa_verified flag set by _complete_admin_login
    # after a valid TOTP. Any admin session WITHOUT it — e.g. a legacy cookie created
    # before 2FA existed — is torn down and bounced to /login for the full flow.
    if not (current_user.is_authenticated and current_user.role == 'admin'):
        return
    if request.endpoint in ('static', 'login', 'logout',
                            'admin_2fa', 'admin_2fa_setup'):
        return
    if not session.get('admin_2fa_verified'):
        logout_user()
        session.clear()
        flash('Verifica la autenticación en dos pasos para continuar.', 'info')
        return redirect(url_for('login'))

# ---------------------------------------------------------------------------
# Context processors (§6.5 + §25.5)
# ---------------------------------------------------------------------------

@app.context_processor
def inject_globals():
    """
    Make `logout_form` available in every template so the nav partial can emit
    a CSRF-protected POST logout button without each route passing it.
    """
    return dict(logout_form=LogoutForm())


# Pixel helpers must be Jinja2 globals, not context-processor values.
# Context processors are invisible inside macros imported without `with context`;
# globals are available everywhere, including inside macro bodies.
app.jinja_env.globals.update(
    pixel_wordmark_pixels=pixel_wordmark_pixels,
    pixel_text_pixels=pixel_text_pixels,
    pixel_text_width=pixel_text_width,
    pixel_text_height=pixel_text_height,
)


@app.template_filter('format_date')
def _format_date(value):
    # Used by dashboard, feed_row, search, and detail templates to render
    # created_at / ai_reviewed_at. None-safe so partially-populated rows
    # (e.g. ai_reviewed_at before moderation) don't 500 the page.
    if value is None:
        return ''
    return value.strftime('%d %b %Y')


# status is an internal state key (English) branched on across the app; it is
# never stored in Spanish. Map it to a Spanish badge label only at render time,
# for the admin views that print it raw. Unknown values fall back to UPPER.
_STATUS_LABELS = {
    'pending':       'PENDIENTE',
    'approved':      'APROBADO',
    'rejected':      'RECHAZADO',
    'flagged':       'REVISIÓN',
    'banned_hidden': 'OCULTO',
}


@app.template_filter('status_label')
def _status_label(value):
    return _STATUS_LABELS.get(value, (value or '').upper())

# ---------------------------------------------------------------------------
# Open-redirect defence at login (§4.1 / H3 / G2.3)
# ---------------------------------------------------------------------------

# SECURITY (G2.3): control + whitespace chars browsers strip from URLs before
# routing. Any of these in a ?next= value means the redirect target is being
# obfuscated — reject outright. Covers C0 controls, space, DEL, and C1/NBSP.
_CONTROL_CHARS = re.compile(r'[\x00-\x20\x7f-\xa0]')


def _is_safe_next(target: str) -> bool:
    """
    SECURITY (audit findings H3 + G2 + G2.3 — open redirect): only allow
    same-origin relative redirects. A naive "no scheme, no netloc, starts with
    /" check is NOT enough — all of these slip through it but redirect off-site
    once a real browser normalises the URL:
      - '///evil.com'        protocol-relative after the browser collapses it
      - '/\\evil.com'         browsers fold backslashes to '/'
      - '/%2f%2fevil.com'    percent-encoded slashes decode to '//evil.com'
      - '/%0a//evil.com'     a stripped newline leaves '//evil.com'
    So we (1) percent-decode, (2) reject ANY control/whitespace char (browsers
    strip these before routing, which can change the destination), (3) fold
    backslashes, (4) require a single-slash-rooted relative path, and finally
    (5) resolve against our own origin with urljoin and confirm the netloc is
    unchanged — the authoritative same-origin test.
    """
    if not target:
        return False
    decoded = unquote(target)
    if _CONTROL_CHARS.search(decoded):
        return False
    decoded = decoded.replace('\\', '/')
    if not decoded.startswith('/') or decoded.startswith('//'):
        return False
    if urlparse(decoded).netloc:                 # belt-and-braces
        return False
    joined = urljoin(request.host_url, decoded)
    return urlparse(joined).netloc == urlparse(request.host_url).netloc

# ---------------------------------------------------------------------------
# Auth routes (§4.1, §20)
# ---------------------------------------------------------------------------

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit('5 per hour', methods=['POST'])
def register():
    form = RegistrationForm()
    # Shown on both the happy path and the "email already registered" path so the
    # two are indistinguishable to the client (audit finding S1, below).
    _sent_msg = ('Te enviamos un enlace de verificación a tu correo. '
                 'Haz clic en él para activar tu cuenta.')
    if form.validate_on_submit():
        # SECURITY (audit finding S1 — account enumeration): a distinct "ya existe
        # ese correo" message turned registration into an oracle for which emails
        # are registered (the login path is deliberately constant-time to avoid
        # exactly this). When the email is already taken, show the SAME generic
        # "we sent a link" message as success and stop — send nothing, reveal
        # nothing. Email is encrypted at rest, so existence is checked by its hash
        # only (the encrypted column is never queryable). (§4.2)
        if User.query.filter_by(email_hash=email_hash(form.email.data)).first():
            flash(_sent_msg, 'info')
            return redirect(url_for('login'))
        # Username collisions are checked case-insensitively (audit finding S2): SQLite
        # treats 'Admin' and 'admin' as distinct, which would allow lookalike
        # impersonation. Revealing username availability is conventional, so this
        # branch keeps its specific message.
        if User.query.filter(
                func.lower(User.username) == form.username.data.lower()).first():
            flash('Ese nombre de usuario ya está en uso.', 'danger')
            return render_template('register.html', form=form)

        # When the user picked "Otro" and typed a custom school, persist that
        # value instead of the sentinel. Strip + cap so we never store padding
        # or values longer than the User.school column allows.
        school_value = form.school.data
        if school_value == SCHOOL_OTHER_SENTINEL:
            typed = (form.school_other.data or '').strip()
            if typed:
                school_value = typed[:64]

        # VERIFY-THEN-CREATE: no User is written here. The registration is carried
        # inside a Fernet-encrypted, 24 h token that we email to the address being
        # claimed; the row is created only when that link is opened (verify_email).
        # The password is hashed up front so the plaintext never travels in the
        # link, and nothing touches the database until the email is proven.
        payload = {
            'username': form.username.data,
            'email':    form.email.data,
            'school':   school_value,
            'grade':    form.grade.data,
            'pw_hash':  generate_password_hash(form.password.data,
                                               method='pbkdf2:sha256'),
        }
        token = make_pending_registration_token(payload)
        link  = url_for('verify_email', token=token, _external=True)
        try:
            send_verification_email(form.email.data, link)
        except Exception:
            # SMTP/connection failure (or missing MAIL_* config): nothing was
            # persisted, so the user can just submit again. Generic retry message.
            # Log the real cause (KeyError on a missing MAIL_* var, auth failure,
            # connection refused, …) — it never reaches the user, so without this
            # the only diagnosis signal is the generic flash.
            current_app.logger.exception('Verification email send failed')
            flash('No pudimos enviar el correo de verificación. '
                  'Inténtalo de nuevo en unos minutos.', 'danger')
            return render_template('register.html', form=form)

        flash(_sent_msg, 'info')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)


@app.route('/verify-email/<token>')
@limiter.limit('20 per hour')
def verify_email(token):
    """Consume a pending-registration token and create the account.

    This is the ONLY place a student User is created — the row exists only once
    the email address has been proven. Idempotent in effect: a second click (or
    a re-used link) finds the account already present and routes to login.
    """
    data = read_pending_registration_token(token)
    if not data:
        flash('El enlace de verificación no es válido o ha expirado. '
              'Regístrate de nuevo.', 'danger')
        return redirect(url_for('register'))

    # The email→click window is unbounded, so re-check uniqueness: the username
    # or email may have been claimed (or this link already used) since the token
    # was minted.
    # Username re-check is case-insensitive to match register() (audit finding S2).
    if (User.query.filter_by(email_hash=email_hash(data['email'])).first()
            or User.query.filter(
                func.lower(User.username) == data['username'].lower()).first()):
        flash('Esa cuenta ya existe. Inicia sesión.', 'info')
        return redirect(url_for('login'))

    user = User(
        username   = data['username'],
        email      = encrypt(data['email']),
        email_hash = email_hash(data['email']),
        school     = data['school'],
        grade      = data['grade'],
        # role defaults to 'student'; is_banned/bio_public default in model.
    )
    # Password was already hashed at /register; assign the hash directly rather
    # than re-hashing a plaintext we deliberately never carried.
    user.password_hash = data['pw_hash']
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        # A concurrent verification (double-click / race) took the unique slot.
        db.session.rollback()
        flash('Esa cuenta ya existe. Inicia sesión.', 'info')
        return redirect(url_for('login'))

    flash('¡Cuenta verificada y creada! Ya puedes iniciar sesión.', 'success')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit('10 per minute')
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(
            email_hash=email_hash(form.email.data)
        ).first()
        # ALWAYS run a password check, even if user doesn't exist.
        # This makes the response time constant regardless of whether the
        # email is registered, defeating timing-based enumeration. (§4.1)
        if user:
            password_ok = user.check_password(form.password.data)
            banned      = user.is_banned
        else:
            check_password_hash(DUMMY_HASH, form.password.data)  # waste time
            password_ok = False
            banned      = False
        if user and password_ok and not banned:
            # ADMIN HARDENING (owner-approved, beyond v4 spec): admins do NOT get an
            # authenticated session on password alone. Hand off to a two-phase TOTP
            # step (enroll first time, verify after).
            if user.role == 'admin':
                # Clear any pre-auth session (session fixation, audit M2) and stash a
                # short-lived pre-2FA marker. login_user is deliberately NOT called yet.
                session.clear()
                session['pre_2fa_uid'] = user.id
                session['pre_2fa_at']  = datetime.now(timezone.utc).isoformat()
                nxt = request.args.get('next')
                if _is_safe_next(nxt):
                    session['pre_2fa_next'] = nxt   # carried across the 2FA step
                if user.totp_secret is None:
                    return redirect(url_for('admin_2fa_setup'))
                return redirect(url_for('admin_2fa'))
            # SECURITY (audit finding M2 — session fixation): clear any
            # pre-auth session contents so a fixed/known session id from before
            # login cannot be ridden into an authenticated context. Flask-Login
            # rotates the remember cookie but does not, by itself, discard a
            # pre-existing anonymous session — so we clear it explicitly.
            session.clear()
            login_user(user)
            # Non-admin sessions are deliberately PERSISTENT: session.permanent
            # makes the cookie carry Max-Age = PERMANENT_SESSION_LIFETIME (14 days,
            # config.py), so a student stays logged in across browser restarts until
            # that window lapses or they log out. This is the explicit counterpart to
            # the admin path (_complete_admin_login), which sets permanent = False so
            # an admin session dies on browser close.
            session.permanent = True
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            # SECURITY (audit finding H3): only honour ?next= if it is a safe,
            # same-origin relative path. Otherwise fall back to the homepage.
            next_url = request.args.get('next')
            if _is_safe_next(next_url):
                return redirect(next_url)
            return redirect(url_for('index'))
        flash('Correo electrónico o contraseña incorrectos.', 'danger')
    return render_template('login.html', form=form)


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    # CSRF on this POST is enforced globally by CSRFProtect; the template
    # carries the token via the injected logout_form (§6.5).
    logout_user()
    flash('Sesión cerrada.', 'info')
    return redirect(url_for('index'))


# ---------------------------------------------------------------------------
# Admin two-factor auth (TOTP) — owner-approved hardening, beyond the v4 spec.
# A correct password only earns a short-lived "pre-2FA" session; an authenticated
# admin session is established by _complete_admin_login ONLY after a valid TOTP.
# ---------------------------------------------------------------------------

PRE_2FA_TTL = timedelta(minutes=5)   # pre-2FA marker expires fast

# Per-account TOTP brute-force lockout (audit MEDIUM). The per-IP rate limit alone
# does not bound a distributed attacker who already has the admin password — a
# botnet just spreads guesses across IPs. These freeze the ACCOUNT (a DB row, not
# the session/IP) after TOTP_MAX_FAILS consecutive bad codes, so clearing cookies
# or rotating source IPs cannot reset it.
TOTP_MAX_FAILS = 5                       # consecutive bad codes before lockout
TOTP_LOCKOUT   = timedelta(minutes=15)   # account-freeze duration


def _totp_lock_remaining(user):
    """Remaining lockout timedelta if `user` is TOTP-locked right now, else None."""
    until = user.totp_locked_until
    if until is None:
        return None
    if until.tzinfo is None:                       # SQLite stores naive -> treat as UTC
        until = until.replace(tzinfo=timezone.utc)
    remaining = until - datetime.now(timezone.utc)
    return remaining if remaining.total_seconds() > 0 else None


def _register_totp_failure(user):
    """Count a failed TOTP; return True if THIS failure tripped the lockout."""
    user.failed_totp_count = (user.failed_totp_count or 0) + 1
    tripped = user.failed_totp_count >= TOTP_MAX_FAILS
    if tripped:
        user.totp_locked_until = datetime.now(timezone.utc) + TOTP_LOCKOUT
        user.failed_totp_count = 0                 # reset; the lock now governs
    db.session.commit()
    return tripped


def _clear_totp_failures(user):
    """Reset the failure counter + lock after a valid TOTP (no-op if already clear)."""
    if user.failed_totp_count or user.totp_locked_until:
        user.failed_totp_count = 0
        user.totp_locked_until = None
        db.session.commit()


def _pre_2fa_user():
    """Resolve the admin awaiting TOTP from the pre-2FA session marker, or None.

    Returns None (caller bounces to /login) if the marker is missing, older than
    PRE_2FA_TTL, or no longer maps to an active admin. Never trusts the session id
    alone — it re-loads the user and re-checks role + ban on every step.
    """
    uid = session.get('pre_2fa_uid')
    started = session.get('pre_2fa_at')
    if not uid or not started:
        return None
    try:
        started_at = datetime.fromisoformat(started)
    except (TypeError, ValueError):
        return None
    if started_at.tzinfo is None:
        started_at = started_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - started_at > PRE_2FA_TTL:
        return None
    user = db.session.get(User, int(uid))
    if user is None or user.is_banned or user.role != 'admin':
        return None
    return user


def _complete_admin_login(user):
    """Finish a two-phase admin login after a verified TOTP code.

    Establishes a NON-PERSISTENT session: login_user(remember=False) sets no
    remember-me cookie, and session.permanent=False makes the session cookie carry
    no Max-Age — so it dies when the browser closes and is never "kept open".
    """
    nxt = session.get('pre_2fa_next')      # capture before clearing
    session.clear()                        # drop every pre-2FA marker (session fixation)
    login_user(user, remember=False)
    session.permanent = False
    # Stamp the session as 2FA-verified. _require_admin_2fa (below) rejects any
    # authenticated admin session WITHOUT this flag, so a session that did not pass
    # through this function (e.g. a legacy cookie minted before 2FA existed) cannot
    # reach admin pages — it is forced back through the full password + TOTP flow.
    session['admin_2fa_verified'] = True
    user.last_login = datetime.now(timezone.utc)
    db.session.commit()
    if _is_safe_next(nxt):
        return redirect(nxt)
    return redirect(url_for('admin'))


def _qr_png_data_uri(data: str) -> str:
    """Render `data` as a QR PNG and return it as a base64 data: URI.

    Embedded via <img src="data:image/png;base64,...">, which the CSP permits
    (img-src 'self' data:). This keeps the QR out of the one |safe field
    (description_html) — no raw markup is injected into the page."""
    # Force the PIL factory (Pillow is already a dependency) so behaviour is
    # deterministic regardless of which optional backends qrcode auto-detects.
    img = qrcode.make(data, image_factory=PilImage)
    buf = BytesIO()
    img.save(buf, format='PNG')
    b64 = base64.b64encode(buf.getvalue()).decode('ascii')
    return f'data:image/png;base64,{b64}'


@app.route('/admin/2fa/setup', methods=['GET', 'POST'])
@limiter.limit('5 per minute;20 per hour', methods=['POST'])
def admin_2fa_setup():
    user = _pre_2fa_user()
    if user is None:
        flash('Vuelve a iniciar sesión.', 'info')
        return redirect(url_for('login'))
    if user.totp_secret is not None:
        # Already enrolled — nothing to set up; go verify instead.
        return redirect(url_for('admin_2fa'))
    form = TwoFactorForm()
    # Per-account lockout (audit MEDIUM): the same freeze applies during enrollment,
    # checked before a QR/secret is issued, so a locked account can't be hammered here.
    remaining = _totp_lock_remaining(user)
    if remaining:
        mins = max(1, ceil(remaining.total_seconds() / 60))
        flash(f'Demasiados intentos fallidos. Inténtalo de nuevo en {mins} min.', 'danger')
        return render_template('admin_2fa_setup.html', form=form, locked=True, lock_minutes=mins)
    # One pending secret per pre-2FA session, held in the session until the admin
    # proves they can generate a code from it. Only THEN is it persisted.
    # SECURITY (audit finding S3): the Flask session cookie is SIGNED, not encrypted,
    # so a raw base32 secret here would be readable in the admin's own cookie before
    # enrollment completes. Fernet-encrypt it in transit (same primitive as the
    # persisted User.totp_secret) and decrypt only when needed.
    stored = session.get('pending_totp_secret')
    if stored:
        try:
            secret = decrypt(stored)
        except Exception:
            secret = None
    else:
        secret = None
    if not secret:
        secret = pyotp.random_base32()
        session['pending_totp_secret'] = encrypt(secret)
    if form.validate_on_submit():
        if totp_verify(secret, form.code.data):
            user.totp_secret = encrypt(secret)
            db.session.commit()
            _clear_totp_failures(user)
            session.pop('pending_totp_secret', None)
            flash('Autenticación en dos pasos activada.', 'success')
            return _complete_admin_login(user)
        if _register_totp_failure(user):
            session.clear()
            mins = int(TOTP_LOCKOUT.total_seconds() // 60)
            flash(f'Demasiados intentos. Tu cuenta quedó bloqueada {mins} minutos.', 'danger')
            return redirect(url_for('login'))
        flash('Código incorrecto. Vuelve a escanear el QR e inténtalo de nuevo.', 'danger')
    uri = totp_provisioning_uri(secret, user.username)
    return render_template('admin_2fa_setup.html', form=form,
                           qr_data_uri=_qr_png_data_uri(uri), manual_key=secret)


@app.route('/admin/2fa', methods=['GET', 'POST'])
@limiter.limit('5 per minute;20 per hour', methods=['POST'])
def admin_2fa():
    user = _pre_2fa_user()
    if user is None:
        flash('Vuelve a iniciar sesión.', 'info')
        return redirect(url_for('login'))
    if user.totp_secret is None:
        return redirect(url_for('admin_2fa_setup'))
    form = TwoFactorForm()
    # Per-account lockout (audit MEDIUM): refuse codes while the account is frozen,
    # BEFORE any verify, so a locked account cannot be probed at all.
    remaining = _totp_lock_remaining(user)
    if remaining:
        mins = max(1, ceil(remaining.total_seconds() / 60))
        flash(f'Demasiados intentos fallidos. Inténtalo de nuevo en {mins} min.', 'danger')
        return render_template('admin_2fa.html', form=form, locked=True, lock_minutes=mins)
    if form.validate_on_submit():
        if totp_verify(decrypt(user.totp_secret), form.code.data):
            _clear_totp_failures(user)
            return _complete_admin_login(user)
        if _register_totp_failure(user):
            # Lockout just tripped: drop the pre-2FA session so the attacker must
            # re-authenticate with the password, and the account stays frozen.
            session.clear()
            mins = int(TOTP_LOCKOUT.total_seconds() // 60)
            flash(f'Demasiados intentos. Tu cuenta quedó bloqueada {mins} minutos.', 'danger')
            return redirect(url_for('login'))
        flash('Código incorrecto. Inténtalo de nuevo.', 'danger')
    return render_template('admin_2fa.html', form=form)


# ---------------------------------------------------------------------------
# Submit routes — Research and Project tracks (§7)
# Two separate functions so url_for('submit_research') and
# url_for('submit_project') both resolve (see AGENTS.md §2).
# ---------------------------------------------------------------------------

@app.route('/submit/research', methods=['GET', 'POST'])
@login_required
@limiter.limit('5 per hour', methods=['POST'])
def submit_research():
    form = ResearchSubmitForm()
    if not form.validate_on_submit():
        return render_template('submit_research.html', form=form)

    upload_folder = current_app.config['UPLOAD_FOLDER']
    papers_folder = os.path.join(upload_folder, 'papers')
    covers_folder = os.path.join(upload_folder, 'covers')

    saved_files = []  # (folder_key, fname) — for orphan cleanup on error
    try:
        # Step 2: primary document (required)
        main_pdf_fname = secure_doc_upload(form.main_pdf.data, papers_folder)
        saved_files.append(('papers', main_pdf_fname))

        # Step 3: optional extra PDFs
        extra_pdf_fnames = []
        for field in (form.extra_pdf_1.data, form.extra_pdf_2.data):
            if field and field.filename:
                fname = secure_doc_upload(field, papers_folder)
                extra_pdf_fnames.append(fname)
                saved_files.append(('papers', fname))

        # Step 3: optional cover image
        cover_fname = None
        if form.cover_image.data and form.cover_image.data.filename:
            cover_fname = secure_image_upload(form.cover_image.data, covers_folder)
            saved_files.append(('covers', cover_fname))

    except ValueError as exc:
        for folder_key, fname in saved_files:
            _delete_file_if_exists(folder_key, fname)
        flash(str(exc), 'danger')
        return render_template('submit_research.html', form=form)

    # Step 4: render Markdown
    description_md   = form.abstract.data
    description_html = render_markdown(description_md)

    # Step 5 + 6: build Submission object (slug set by helper in step 7)
    base_slug  = f"{make_unique_slug(form.title.data)}-{uuid.uuid4().hex[:6]}"
    submission = Submission(
        track            = 'research',
        status           = 'pending',
        author_id        = current_user.id,
        title            = form.title.data,
        description_md   = description_md,
        description_html = description_html,
        category         = form.category.data,
        tags             = sanitize_tags(form.tags.data),
        cover_image      = cover_fname,
        external_link    = form.external_link.data or None,
        ib_type          = form.ib_type.data,
        ib_subject       = form.ib_subject.data or None,
        word_count       = form.word_count.data,
        academic_year    = form.academic_year.data,
        main_pdf         = main_pdf_fname,
        extra_pdfs       = ','.join(extra_pdf_fnames) if extra_pdf_fnames else None,
    )

    # Step 7: atomic INSERT with slug-collision retry
    _try_commit_submission_with_slug(submission, base_slug)

    # Step 8: AI content moderation (10 s timeout, never raises). run_ai_moderation
    # itself swallows API errors; this guard only covers the db.session.commit. Log
    # it (audit hygiene) instead of swallowing silently — the submission is already
    # safely persisted by step 7, so a failed moderation commit is non-fatal.
    try:
        run_ai_moderation(submission, log_to_db=True)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            'Post-submit moderation commit failed for submission %s', submission.id)

    # Step 9
    flash('Tu trabajo fue enviado. Lo revisaremos en breve.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/submit/project', methods=['GET', 'POST'])
@login_required
@limiter.limit('5 per hour', methods=['POST'])
def submit_project():
    form = ProjectSubmitForm()
    if not form.validate_on_submit():
        return render_template('submit_project.html', form=form)

    upload_folder = current_app.config['UPLOAD_FOLDER']
    covers_folder = os.path.join(upload_folder, 'covers')
    extras_folder = os.path.join(upload_folder, 'extras')
    # SECURITY (§4.9 M1): project documents live outside static/. Served only
    # via download_document (always as_attachment + nosniff), except a validated
    # main PDF, which that route may serve inline with application/pdf + nosniff.
    doc_folder = os.path.join(current_app.instance_path, 'uploads', 'documents')

    saved_files = []  # (folder_key, fname) — for orphan cleanup on error
    try:
        # Step 2: cover image (required by ProjectSubmitForm)
        cover_fname = secure_image_upload(form.cover_image.data, covers_folder)
        saved_files.append(('covers', cover_fname))

        # Step 3: optional extra images
        extra_image_fnames = []
        for field in (form.extra_image_1.data, form.extra_image_2.data,
                      form.extra_image_3.data):
            if field and field.filename:
                fname = secure_image_upload(field, extras_folder)
                extra_image_fnames.append(fname)
                saved_files.append(('extras', fname))

        # Step 3: optional project documents (stored outside static/)
        docs_list = []

        # Main PDF (optional) — shown inline on the detail page. Flagged is_main
        # and prepended so it's distinguishable from supplementary downloads.
        if form.main_pdf.data and form.main_pdf.data.filename:
            original_name = form.main_pdf.data.filename
            fname         = secure_doc_upload(form.main_pdf.data, doc_folder)
            size_kb       = os.path.getsize(
                os.path.join(doc_folder, fname)
            ) // 1024
            docs_list.append({
                'filename':      fname,
                'original_name': original_name,
                'size_kb':       size_kb,
                'type':          'pdf',
                'is_main':       True,
            })
            saved_files.append(('documents', fname))

        # Supplementary documents (download-only, any allowed type).
        for field in (form.document_1.data, form.document_2.data,
                      form.document_3.data):
            if field and field.filename:
                original_name = field.filename
                ext           = original_name.rsplit('.', 1)[-1].lower()
                fname         = secure_doc_upload(field, doc_folder)
                size_kb       = os.path.getsize(
                    os.path.join(doc_folder, fname)
                ) // 1024
                docs_list.append({
                    'filename':      fname,
                    'original_name': original_name,
                    'size_kb':       size_kb,
                    'type':          ext,
                })
                saved_files.append(('documents', fname))

    except ValueError as exc:
        for folder_key, fname in saved_files:
            _delete_file_if_exists(folder_key, fname)
        flash(str(exc), 'danger')
        return render_template('submit_project.html', form=form)

    # Step 4: render Markdown
    description_md   = form.description.data
    description_html = render_markdown(description_md)

    # Step 5 + 6: build Submission object (slug set by helper in step 7)
    base_slug  = f"{make_unique_slug(form.title.data)}-{uuid.uuid4().hex[:6]}"
    submission = Submission(
        track            = 'project',
        status           = 'pending',
        author_id        = current_user.id,
        title            = form.title.data,
        description_md   = description_md,
        description_html = description_html,
        category         = form.category.data,
        tags             = sanitize_tags(form.tags.data),
        cover_image      = cover_fname,
        external_link    = form.external_link.data or None,
        project_type     = form.project_type.data,
        extra_images     = ','.join(extra_image_fnames) if extra_image_fnames else None,
        documents        = json.dumps(docs_list) if docs_list else None,
        code_snippet     = form.code_snippet.data or None,
    )

    # Step 7: atomic INSERT with slug-collision retry
    _try_commit_submission_with_slug(submission, base_slug)

    # Step 8: AI content moderation (10 s timeout, never raises). See submit_research
    # for why a failed commit here is logged-and-ignored rather than swallowed.
    try:
        run_ai_moderation(submission, log_to_db=True)
        db.session.commit()
    except Exception:
        db.session.rollback()
        current_app.logger.exception(
            'Post-submit moderation commit failed for submission %s', submission.id)

    # Step 9
    flash('Tu trabajo fue enviado. Lo revisaremos en breve.', 'success')
    return redirect(url_for('dashboard'))


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    return render_template('500.html'), 500


@app.errorhandler(413)
def payload_too_large(e):
    # audit finding B1: oversize uploads hit MAX_CONTENT_LENGTH and abort before any
    # view runs, so the user would otherwise see a bare Werkzeug error. Reuse the 500
    # template with an explanatory flash about the size limit.
    flash('Los archivos superan el tamaño permitido. Reduce su tamaño '
          '(máx. 20 MB por documento, 5 MB por imagen) e inténtalo de nuevo.',
          'danger')
    return render_template('500.html'), 413


@app.errorhandler(429)
def rate_limited(e):
    # audit finding B1: surface Flask-Limiter rejections as a friendly page instead
    # of the default plain-text 429.
    flash('Demasiadas solicitudes en poco tiempo. Espera un momento e '
          'inténtalo de nuevo.', 'warning')
    return render_template('500.html'), 429


# ---------------------------------------------------------------------------
# Home page (§10)
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    from sqlalchemy import func

    if current_user.is_authenticated:
        recent_research, recent_projects = recommend_split_for_user(current_user.id)
    else:
        recent_research, recent_projects = recommend_split_for_guest()

    hero_stats = {
        'research_count': db.session.query(func.count(Submission.id))
                            .filter_by(status='approved', track='research').scalar() or 0,
        'project_count':  db.session.query(func.count(Submission.id))
                            .filter_by(status='approved', track='project').scalar() or 0,
        'school_count':   db.session.query(func.count(func.distinct(User.school)))
                            .join(Submission, Submission.author_id == User.id)
                            .filter(Submission.status == 'approved').scalar() or 0,
    }

    return render_template('index.html',
                           recent_research=recent_research,
                           recent_projects=recent_projects,
                           hero_stats=hero_stats)


# ---------------------------------------------------------------------------
# Browse route — Track Totals + Filter + Sort + Pagination (§14)
# ---------------------------------------------------------------------------

@app.route('/browse')
def browse():
    from sqlalchemy import func, case

    track    = request.args.get('track', '').strip()
    category = request.args.get('category', '').strip()
    sort     = request.args.get('sort', 'newest').strip()
    page     = request.args.get('page', 1, type=int)

    # Totals strip — per-track counts of the approved corpus. When a category is
    # active the counts are scoped to that category so each pill matches the
    # results grid (QA finding: an unscoped pill read "3 INVESTIGACIONES" while
    # only 1 result showed). The track filter is deliberately NOT applied — the
    # pills are track switches, so each must still show its own track's count.
    totals_q = (
        db.session.query(
            func.count(Submission.id).label('all'),
            func.sum(case((Submission.track == 'research', 1), else_=0)).label('research'),
            func.sum(case((Submission.track == 'project',  1), else_=0)).label('project'),
        )
        .filter(Submission.status == 'approved')
    )
    if category:
        totals_q = totals_q.filter(Submission.category == category)
    totals_row = totals_q.first()
    totals = {
        'all':      int(totals_row.all or 0),
        'research': int(totals_row.research or 0),
        'project':  int(totals_row.project or 0),
    }

    # Main result query. joinedload(author) avoids the per-card author N+1 (P1).
    q = Submission.query.options(joinedload(Submission.author)).filter_by(status='approved')
    if track in ('research', 'project'):
        q = q.filter_by(track=track)
    if category:
        q = q.filter_by(category=category)

    if sort == 'views':
        q = q.order_by(Submission.views.desc(), Submission.created_at.desc())
    else:  # 'newest' or anything else falls back to recency
        q = q.order_by(Submission.created_at.desc())

    submissions = q.paginate(page=page, per_page=12, error_out=False)

    # Distinct categories for sidebar — limited to the active track if one is set.
    cat_query = db.session.query(Submission.category).filter_by(status='approved')
    if track in ('research', 'project'):
        cat_query = cat_query.filter_by(track=track)
    categories = sorted({c for (c,) in cat_query.distinct().all() if c})

    return render_template('browse.html',
                           submissions=submissions,
                           totals=totals,
                           categories=categories,
                           active_track=track,
                           active_category=category,
                           active_sort=sort)


# ---------------------------------------------------------------------------
# Full-text search (§12) — FTS5 over the submissions_fts virtual table, plus
# a category match and a fuzzy fallback (no DB schema change).
#
# 1. FTS5 MATCH over title/description/tags (helpers.sanitise_fts_query escapes
#    user input — hyphens become phrase matches, reserved tokens are stripped;
#    an empty cleaned query sets sanitised_empty=True so the template can say
#    "your input was only operators/punctuation").
# 2. A plain LIKE on the `category` column so category names are searchable
#    without re-indexing FTS.
# 3. If nothing matches, helpers.fuzzy_search runs a rapidfuzz pass over the
#    same columns to tolerate misspellings ("karna" -> "karina"); the template
#    then shows an "approximate results" banner (fuzzy=True).
#
# The route loads real Submission ORM objects (not raw rows) so card.html can
# read item.author / item.likes.
# ---------------------------------------------------------------------------

@app.route('/search')
def search():
    from sqlalchemy import func

    q     = request.args.get('q', '').strip()
    track = request.args.get('track', '')
    results = []
    sanitised_empty = False
    fuzzy = False

    if q:
        # 1. FTS text match — ids in rank order.
        ordered_ids = []
        fts_query = sanitise_fts_query(q)
        if not fts_query:
            sanitised_empty = True
        else:
            fts_sql = """
                SELECT s.id
                FROM submissions s
                JOIN submissions_fts f ON s.id = f.rowid
                WHERE submissions_fts MATCH :query
                  AND s.status = 'approved'
            """
            params = {'query': fts_query}
            if track in ('research', 'project'):
                fts_sql += ' AND s.track = :track'
                params['track'] = track
            fts_sql += ' ORDER BY rank LIMIT 30'
            ordered_ids = [row.id for row in
                           db.session.execute(db.text(fts_sql), params).fetchall()]

        # 2. Category match (regular column) — append ids not already present.
        if not sanitised_empty:
            cat_q = (Submission.query
                     .filter(Submission.status == 'approved')
                     .filter(func.lower(Submission.category).like(f'%{q.lower()}%')))
            if track in ('research', 'project'):
                cat_q = cat_q.filter(Submission.track == track)
            seen = set(ordered_ids)
            for (cid,) in cat_q.with_entities(Submission.id).all():
                if cid not in seen:
                    ordered_ids.append(cid)
                    seen.add(cid)

        # 3. Fuzzy fallback when exact passes found nothing.
        if not sanitised_empty and not ordered_ids:
            ordered_ids = fuzzy_search(db.session, q, track=track or None)
            fuzzy = bool(ordered_ids)

        # Load ORM objects and restore the ranked order.
        if ordered_ids:
            objs = {s.id: s for s in
                    Submission.query.options(joinedload(Submission.author))
                    .filter(Submission.id.in_(ordered_ids)).all()}
            results = [objs[i] for i in ordered_ids if i in objs]

    return render_template('search.html',
                           results=results, q=q, track=track,
                           sanitised_empty=sanitised_empty, fuzzy=fuzzy)


# ---------------------------------------------------------------------------
# Hardened document download (§4.9 M1 + G2.1) — project documents live OUTSIDE
# static/. Non-PDF types are NEVER served inline; only validated PDFs may be
# (with ?inline=1) so the project detail page can embed a main PDF, served as
# application/pdf + nosniff (deliberate narrowing of the §4.9 M1 never-inline
# rule — see CLAUDE.md / AGENTS.md). Every download checks:
#   (1) The submission is approved, OR the requester is the author/admin.
#       Otherwise abort(404) — same shape as the detail-page visibility rule,
#       so the file's existence is never leaked for flagged/rejected items.
#   (2) The requested filename appears in submission.documents (the JSON
#       manifest written at submit time). Defends against path traversal and
#       enumeration: a UUID alone is no longer enough — it must belong to THIS
#       submission. send_from_directory then sandboxes the join.
# The response sets `X-Content-Type-Options: nosniff` and forces
# `as_attachment=True` for everything except an explicit ?inline=1 request for a
# PDF, so a browser cannot content-sniff a malicious .md/.txt into HTML.
# ---------------------------------------------------------------------------

@app.route('/download/document/<int:submission_id>/<path:filename>')
def download_document(submission_id, filename):
    submission = Submission.query.get_or_404(submission_id)

    is_owner = (current_user.is_authenticated and
                current_user.id == submission.author_id)
    is_admin = (current_user.is_authenticated and
                current_user.role == 'admin')
    if submission.status != 'approved' and not (is_owner or is_admin):
        abort(404)

    allowed = {}  # filename -> declared type (extension)
    if submission.documents:
        try:
            allowed = {d['filename']: d.get('type', '')
                       for d in json.loads(submission.documents)}
        except (json.JSONDecodeError, TypeError, KeyError):
            allowed = {}
    if filename not in allowed:
        abort(404)

    # Inline rendering is permitted ONLY for PDFs (validated at upload by
    # secure_doc_upload: magic-byte + fitz structural parse). Served with an
    # explicit application/pdf type and nosniff so the browser honours the type
    # and cannot re-sniff the bytes into HTML. Every other type — and any
    # request without ?inline=1 — is forced to download as an attachment.
    inline = request.args.get('inline') == '1' and allowed[filename] == 'pdf'
    resp = send_from_directory(
        os.path.join(current_app.instance_path, 'uploads', 'documents'),
        filename,
        as_attachment=not inline,
        mimetype='application/pdf' if inline else None,
    )
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    return resp


# ---------------------------------------------------------------------------
# School leaderboard (§11) — single conditional-aggregation query.
# Context key is `schools`: each row exposes .school, .total, .research_count,
# .project_count (labels chosen to read clearly in the template).
# ---------------------------------------------------------------------------

@app.route('/leaderboard')
def leaderboard():
    from sqlalchemy import func, case
    schools = (
        db.session.query(
            User.school,
            func.count(Submission.id).label('total'),
            func.sum(
                case((Submission.track == 'research', 1), else_=0)
            ).label('research_count'),
            func.sum(
                case((Submission.track == 'project', 1), else_=0)
            ).label('project_count'),
        )
        .join(Submission, Submission.author_id == User.id)
        .filter(Submission.status == 'approved')
        .group_by(User.school)
        .order_by(func.count(Submission.id).desc())
        .all()
    )
    return render_template('leaderboard.html', schools=schools)


# ---------------------------------------------------------------------------
# User dashboard (§20 route table) — the author's own submissions and their
# moderation status. The frontend dashboard template iterates `items` and shows
# title, track badge, status badge, views, created date, and a delete button
# per row. Rejected rows additionally surface `mod_flag_reason` so the student
# sees the admin's note (mirrored from ModerationLog by admin_reject, §19.2
# G2.6) and can fix and resubmit.
# ---------------------------------------------------------------------------

@app.route('/dashboard')
@login_required
def dashboard():
    submissions = (Submission.query
                   .filter_by(author_id=current_user.id)
                   .order_by(Submission.created_at.desc())
                   .all())
    return render_template('dashboard.html', submissions=submissions,
                           delete_form=DeleteSubmissionForm())


# ---------------------------------------------------------------------------
# Public profile (§13) — 2 queries: the user + one combined stats aggregation.
# ---------------------------------------------------------------------------

@app.route('/profile/<username>')
def profile(username):
    from sqlalchemy import func, case

    user = User.query.filter_by(username=username).first_or_404()
    if user.is_banned and not (current_user.is_authenticated and
                               current_user.role == 'admin'):
        abort(404)

    stats_row = (
        db.session.query(
            func.count(Submission.id).label('total'),
            func.sum(
                case((Submission.track == 'research', 1), else_=0)
            ).label('research'),
            func.coalesce(func.sum(Submission.views), 0).label('views'),
        )
        .filter(Submission.author_id == user.id,
                Submission.status == 'approved')
        .first()
    )
    stats = {
        'total':    stats_row.total    or 0,
        'research': int(stats_row.research or 0),
        'views':    int(stats_row.views    or 0),
    }

    # joinedload(author) avoids the per-card author N+1 on the profile grids (P1).
    research = (Submission.query.options(joinedload(Submission.author))
                .filter_by(author_id=user.id, status='approved', track='research')
                .order_by(Submission.created_at.desc())
                .paginate(page=request.args.get('rpage', 1, type=int), per_page=9))
    projects = (Submission.query.options(joinedload(Submission.author))
                .filter_by(author_id=user.id, status='approved', track='project')
                .order_by(Submission.created_at.desc())
                .paginate(page=request.args.get('ppage', 1, type=int), per_page=9))

    is_own_profile = (current_user.is_authenticated and
                      current_user.id == user.id)
    # The owner always sees their own bio (even when private); bio_public only
    # gates visibility for OTHER viewers. (§13 audit finding C6)
    bio = decrypt(user.bio) if (user.bio and (is_own_profile or user.bio_public)) else None

    return render_template('profile.html', user=user, bio=bio,
                           research=research, projects=projects,
                           stats=stats, is_own_profile=is_own_profile)


# ---------------------------------------------------------------------------
# Edit profile (§13) — decrypt on GET, encrypt on POST. Avatar upload reuses
# helpers.secure_image_upload (EXIF transpose + decompression-bomb guard) and
# the old avatar file is removed on successful replacement so the avatars/
# folder cannot accumulate orphans across edits.
# ---------------------------------------------------------------------------

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
@limiter.limit('10 per hour', methods=['POST'])
def edit_profile():
    form = ProfileEditForm()
    # Known school select values, used to decide whether to pre-fill the
    # "Otro" text input on GET.
    _school_keys = {key for key, _label in SCHOOL_CHOICES}
    if request.method == 'GET':
        form.bio.data          = decrypt(current_user.bio) if current_user.bio else ''
        form.bio_public.data   = current_user.bio_public
        # If the stored school is one of the canned choices, select it.
        # Otherwise drop into the "Otro" sentinel and pre-fill the text input
        # with the custom value so the user can edit it.
        if current_user.school in _school_keys:
            form.school.data       = current_user.school
            form.school_other.data = ''
        elif current_user.school:
            form.school.data       = SCHOOL_OTHER_SENTINEL
            form.school_other.data = current_user.school
        else:
            form.school.data       = ''
            form.school_other.data = ''
        form.grade.data        = current_user.grade
        form.skills_tags.data  = current_user.skills_tags or ''
        form.linkedin_url.data = current_user.linkedin_url or ''
        form.github_url.data   = current_user.github_url or ''
    if form.validate_on_submit():
        # SECURITY (§4.2): bio is Fernet-encrypted at rest. Empty bio → NULL so
        # we never store an encrypted empty string.
        current_user.bio          = encrypt(form.bio.data) if form.bio.data else None
        current_user.bio_public   = form.bio_public.data
        # Same "Otro" substitution as register() — see that route for the why.
        school_value = form.school.data
        if school_value == SCHOOL_OTHER_SENTINEL:
            typed = (form.school_other.data or '').strip()
            if typed:
                school_value = typed[:64]
        current_user.school       = school_value
        current_user.grade        = form.grade.data
        current_user.skills_tags  = sanitize_tags(form.skills_tags.data, max_tags=8)
        current_user.linkedin_url = form.linkedin_url.data or None
        current_user.github_url   = form.github_url.data or None
        if form.avatar.data and form.avatar.data.filename:
            try:
                fname = secure_image_upload(
                    form.avatar.data,
                    os.path.join(current_app.config['UPLOAD_FOLDER'], 'avatars'),
                    max_px=400,
                )
                # Delete old avatar AFTER the new one is safely on disk so a
                # failed upload can't leave the user with no avatar at all.
                if current_user.avatar_filename:
                    old = os.path.join(
                        current_app.config['UPLOAD_FOLDER'], 'avatars',
                        current_user.avatar_filename,
                    )
                    if os.path.exists(old):
                        try:
                            os.remove(old)
                        except OSError as e:
                            current_app.logger.warning(
                                f'Could not delete old avatar {old}: {e}'
                            )
                current_user.avatar_filename = fname
            except ValueError as e:
                flash(str(e), 'danger')
                return render_template('edit_profile.html', form=form)
        elif form.remove_avatar.data and current_user.avatar_filename:
            # No new upload, but the user asked to clear their current photo.
            old = os.path.join(
                current_app.config['UPLOAD_FOLDER'], 'avatars',
                current_user.avatar_filename,
            )
            if os.path.exists(old):
                try:
                    os.remove(old)
                except OSError as e:
                    current_app.logger.warning(
                        f'Could not delete avatar {old}: {e}'
                    )
            current_user.avatar_filename = None
        db.session.commit()
        flash('Perfil actualizado.', 'success')
        return redirect(url_for('profile', username=current_user.username))
    return render_template('edit_profile.html', form=form)


# ---------------------------------------------------------------------------
# Detail pages — Research and Project (§15). Two thin endpoints share one
# helper so url_for('research_detail') and url_for('project_detail') both
# resolve (the frontend card partial links to whichever matches the track).
# ---------------------------------------------------------------------------

@app.route('/research/<slug>')
def research_detail(slug):
    return _detail_for('research', slug, 'research_detail.html')


@app.route('/project/<slug>')
def project_detail(slug):
    return _detail_for('project', slug, 'project_detail.html')


def _detail_for(track, slug, template):
    submission = Submission.query.filter_by(slug=slug, track=track).first_or_404()

    # Non-approved submissions are visible only to their author or admins.
    # Everyone else gets 404 (not 403) so the slug's existence isn't leaked.
    is_owner = (current_user.is_authenticated and
                current_user.id == submission.author_id)
    is_admin = (current_user.is_authenticated and
                current_user.role == 'admin')
    if submission.status != 'approved' and not (is_owner or is_admin):
        abort(404)

    # View count + true-upsert view history (recency signal for recommendations).
    # SECURITY/correctness (audit finding B2): the old code did `submission.views += 1`
    # then committed on EVERY GET, which (a) let anyone inflate a count by holding F5,
    # (b) lost increments to a read-modify-write race, and (c) wrote on every view.
    # Now: never count the author/admin, count each real viewer at most once (per-user
    # via ViewHistory, per-guest via a capped session list), and increment with an
    # atomic UPDATE so concurrent views can't clobber each other.
    count_view = not (is_owner or is_admin)
    if current_user.is_authenticated:
        existing_view = ViewHistory.query.filter_by(
            user_id=current_user.id, submission_id=submission.id
        ).first()
        if existing_view:
            existing_view.viewed_at = datetime.now(timezone.utc)
            count_view = False          # already counted on the first visit
        else:
            db.session.add(ViewHistory(
                user_id=current_user.id,
                submission_id=submission.id,
                viewed_at=datetime.now(timezone.utc),
            ))
    elif count_view:
        # Guests have no ViewHistory row; de-dup with a small per-session memory so a
        # refresh doesn't inflate. Cap the list so the cookie can't grow unbounded.
        seen = session.get('viewed_ids') or []
        if submission.id in seen:
            count_view = False
        else:
            session['viewed_ids'] = (seen + [submission.id])[-50:]

    if count_view:
        Submission.query.filter_by(id=submission.id).update(
            {'views': Submission.views + 1}, synchronize_session=False)
        submission.views += 1           # reflect the new total in THIS render only

    db.session.commit()

    user_liked = False
    if current_user.is_authenticated:
        user_liked = (SubmissionLike.query
                      .filter_by(user_id=current_user.id, submission_id=submission.id)
                      .first() is not None)

    # Read the denormalised counter (audit finding P1) instead of a COUNT(*).
    like_count = submission.like_count

    # SECURITY/robustness (§15 audit finding C4): a malformed ai_report must
    # never 500 the PUBLIC detail page. Treat any parse failure as "no report".
    report = None
    if submission.ai_report:
        try:
            report = json.loads(submission.ai_report)
        except (json.JSONDecodeError, TypeError):
            current_app.logger.warning(
                f'Malformed ai_report on submission {submission.id}; '
                f'rendering detail page without the AI panel.'
            )
            report = None

    related = (Submission.query
               .filter(Submission.status == 'approved',
                       Submission.track == track,
                       Submission.category == submission.category,
                       Submission.id != submission.id)
               .order_by(Submission.created_at.desc())
               .limit(5).all())

    return render_template(template,
                           submission=submission,
                           report=report,
                           user_liked=user_liked,
                           like_count=like_count,
                           related=related)


# ---------------------------------------------------------------------------
# Like route (§17) — toggle like via AJAX. Returns JSON {liked, count} so the
# frontend (§11) can update the heart icon + count without a page reload.
# CSRF is enforced globally by CSRFProtect via the X-CSRFToken header the
# client JS attaches (§4.9 H1).
# ---------------------------------------------------------------------------

@app.route('/<track>/<slug>/like', methods=['POST'])
@login_required
@limiter.limit('60 per minute', methods=['POST'])
def like(track, slug):
    if track not in ('research', 'project'):
        abort(404)
    submission = Submission.query.filter_by(slug=slug, track=track,
                                            status='approved').first_or_404()
    existing = SubmissionLike.query.filter_by(
        user_id=current_user.id, submission_id=submission.id
    ).first()
    if existing:
        db.session.delete(existing)
        liked = False
    else:
        db.session.add(SubmissionLike(user_id=current_user.id,
                                      submission_id=submission.id))
        liked = True
    try:
        db.session.commit()
    except IntegrityError:
        # robustness (audit finding L1): a rapid double-click can race two
        # INSERTs against the composite PK. The like already exists — that is
        # the intended end state, so treat it as success.
        db.session.rollback()
        liked = True
    except (StaleDataError, InvalidRequestError):
        # robustness (audit finding G2.7): the mirror case — a rapid double
        # UNLIKE can have the second DELETE target a row the first already
        # removed, raising StaleDataError (rows-matched 0) instead of
        # IntegrityError. The row is gone, which is the intended end state.
        db.session.rollback()
        liked = False
    # PERF (audit finding P1): keep the denormalised Submission.like_count in sync.
    # Recompute the authoritative total from the source table and persist it so list
    # pages can read the column instead of a per-card COUNT. Doing it here (the single
    # write path) — rather than +/-1 on the optimistic `liked` flag — makes the column
    # self-healing: it always equals the real count even after the double-click races
    # handled above. The COUNT runs only on this write, never on render.
    count = SubmissionLike.query.filter_by(submission_id=submission.id).count()
    submission.like_count = count
    db.session.commit()
    return jsonify({'liked': liked, 'count': count})


# ---------------------------------------------------------------------------
# Delete submission (§18) — author-or-admin only, POST with CSRF, file cleanup.
# Orphan files are routed through helpers._delete_file_if_exists which knows
# documents/ lives under instance/uploads/ (G1) and everything else under the
# static UPLOAD_FOLDER. Malformed documents JSON is logged and skipped rather
# than blocking the DB row delete.
# ---------------------------------------------------------------------------

@app.route('/<track>/<slug>/delete', methods=['POST'])
@login_required
@limiter.limit('10 per hour', methods=['POST'])
def delete_submission(track, slug):
    if track not in ('research', 'project'):
        abort(404)
    submission = Submission.query.filter_by(slug=slug, track=track).first_or_404()
    if submission.author_id != current_user.id and current_user.role != 'admin':
        abort(403)

    if submission.cover_image:
        _delete_file_if_exists('covers', submission.cover_image)

    if submission.track == 'research':
        _delete_file_if_exists('papers', submission.main_pdf)
        if submission.extra_pdfs:
            for fn in submission.extra_pdfs.split(','):
                _delete_file_if_exists('papers', fn.strip())
    else:  # project
        if submission.extra_images:
            for fn in submission.extra_images.split(','):
                _delete_file_if_exists('extras', fn.strip())
        if submission.documents:
            try:
                doclist = json.loads(submission.documents)
                for d in doclist:
                    _delete_file_if_exists('documents', d.get('filename'))
            except (json.JSONDecodeError, TypeError):
                current_app.logger.warning(
                    f'Submission {submission.id} has malformed documents JSON'
                )

    db.session.delete(submission)
    db.session.commit()

    flash('Trabajo eliminado.', 'success')
    return redirect(url_for('dashboard'))


# ---------------------------------------------------------------------------
# Admin routes (§19) — moderation queue + user management.
#
# Every route in this section repeats `if current_user.role != 'admin': abort(403)`
# as its first statement. This is intentional and grep-able: it makes the
# privilege check visible on every function instead of hiding it inside a
# decorator. @login_required handles "logged in"; this line handles "is admin".
# CSRF on the POST routes is enforced globally by CSRFProtect (§4.9 H1); the
# default rate limit (200/hr) from the Limiter at the top of this file covers
# every admin endpoint per §20.
# ---------------------------------------------------------------------------

@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        abort(403)
    pending  = (Submission.query
                .filter_by(status='pending')
                .order_by(Submission.created_at.asc()).all())
    flagged  = (Submission.query
                .filter_by(status='flagged')
                .order_by(Submission.created_at.asc()).all())
    rejected = (Submission.query
                .filter_by(status='rejected')
                .order_by(Submission.updated_at.desc()).all())
    return render_template('admin.html',
                           pending=pending, flagged=flagged, rejected=rejected,
                           reject_form=RejectForm())


@app.route('/admin/approve/<int:id>', methods=['POST'])
@login_required
def admin_approve(id):
    if current_user.role != 'admin':
        abort(403)
    submission = Submission.query.get_or_404(id)
    # Quality review is best-effort: a Gemini timeout/error must NOT block the
    # human approval. Admin gets a warning flash directing them to re-run it
    # later via admin_rereview (§19.5).
    try:
        report = run_ai_review(submission)
        submission.ai_report      = json.dumps(report)
        submission.ai_reviewed_at = datetime.now(timezone.utc)
    except RuntimeError as e:
        current_app.logger.warning(f'AI review failed for submission {id}: {e}')
        flash('Aprobado sin revisión de IA (error de Gemini). Ejecuta la revisión '
              'de IA más tarde desde la página de detalles del trabajo.', 'warning')
    submission.status     = 'approved'
    submission.updated_at = datetime.now(timezone.utc)
    db.session.add(ModerationLog(
        submission_id=submission.id,
        action='human_approved',
        actor=current_user.username,
    ))
    db.session.commit()
    flash('Trabajo aprobado.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/reject/<int:id>', methods=['POST'])
@login_required
def admin_reject(id):
    if current_user.role != 'admin':
        abort(403)
    form = RejectForm()
    if not form.validate_on_submit():
        flash('Debes incluir un motivo de al menos 10 caracteres.', 'danger')
        return redirect(url_for('admin'))
    submission = Submission.query.get_or_404(id)
    submission.status     = 'rejected'
    submission.updated_at = datetime.now(timezone.utc)
    # UX/transparency (audit finding G2.6): the ModerationLog is admin-only, so
    # the student never saw WHY their work was rejected. Mirror the note onto
    # mod_flag_reason, which the dashboard surfaces to the author so they can
    # fix and resubmit.
    submission.mod_flag_reason = form.note.data[:500]
    db.session.add(ModerationLog(
        submission_id=submission.id,
        action='human_rejected',
        actor=current_user.username,
        note=form.note.data[:500],
    ))
    db.session.commit()
    flash('Trabajo rechazado.', 'info')
    return redirect(url_for('admin'))


@app.route('/admin/override/<int:id>', methods=['POST'])
@login_required
def admin_override(id):
    if current_user.role != 'admin':
        abort(403)
    submission = Submission.query.get_or_404(id)
    if submission.status != 'flagged':
        flash('Solo trabajos marcados pueden ser anulados.', 'warning')
        return redirect(url_for('admin'))
    try:
        report = run_ai_review(submission)
        submission.ai_report      = json.dumps(report)
        submission.ai_reviewed_at = datetime.now(timezone.utc)
    except RuntimeError as e:
        current_app.logger.warning(f'AI review failed during override of {id}: {e}')
    submission.status     = 'approved'
    submission.updated_at = datetime.now(timezone.utc)
    db.session.add(ModerationLog(
        submission_id=submission.id,
        action='human_override',
        actor=current_user.username,
        note='Approved despite AI flag.',
    ))
    db.session.commit()
    flash('Marca de IA anulada y trabajo aprobado.', 'success')
    return redirect(url_for('admin'))


@app.route('/admin/remoderate/<int:id>', methods=['POST'])
@login_required
def admin_remoderate(id):
    if current_user.role != 'admin':
        abort(403)
    submission = Submission.query.get_or_404(id)
    # log_to_db=False is load-bearing: in v3 a re-moderation produced TWO log
    # rows (one ai_*, one human_remoderate). The human-triggered row below is
    # the audit-relevant one and already summarises the AI's decision.
    result = run_ai_moderation(submission, log_to_db=False)
    db.session.add(ModerationLog(
        submission_id=submission.id,
        action='human_remoderate',
        actor=current_user.username,
        note=f"Re-triggered AI moderation; is_appropriate={result.get('is_appropriate')} "
             f"flag_reason={result.get('flag_reason') or 'n/a'}",
    ))
    db.session.commit()
    flash('Moderación re-ejecutada.', 'info')
    return redirect(url_for('admin'))


@app.route('/admin/rereview/<int:id>', methods=['POST'])
@login_required
def admin_rereview(id):
    if current_user.role != 'admin':
        abort(403)
    submission = Submission.query.get_or_404(id)
    if submission.status != 'approved':
        flash('Solo se puede reseñar trabajos aprobados.', 'warning')
        return redirect(url_for('admin'))
    # Server-side enforcement of the "re-run only when missing" rule. The
    # frontend (§19.5) hides the button when a report exists, but a forged POST
    # must not be able to overwrite an existing ai_report.
    if submission.ai_report:
        flash('La revisión de IA ya existe.', 'info')
        return redirect(url_for('research_detail', slug=submission.slug)
                        if submission.track == 'research'
                        else url_for('project_detail', slug=submission.slug))
    try:
        report = run_ai_review(submission)
        submission.ai_report      = json.dumps(report)
        submission.ai_reviewed_at = datetime.now(timezone.utc)
        db.session.add(ModerationLog(
            submission_id=submission.id,
            action='human_rereview',
            actor=current_user.username,
            note='Re-ran AI quality review (previous attempt was missing/failed).',
        ))
        db.session.commit()
        flash('Revisión de IA completada.', 'success')
    except RuntimeError as e:
        current_app.logger.warning(f'AI re-review failed for {id}: {e}')
        flash('La revisión de IA falló de nuevo. Inténtalo más tarde.', 'danger')
    return redirect(url_for('research_detail', slug=submission.slug)
                    if submission.track == 'research'
                    else url_for('project_detail', slug=submission.slug))


@app.route('/admin/users')
@login_required
def admin_users():
    if current_user.role != 'admin':
        abort(403)
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)


@app.route('/admin/ban/<int:id>', methods=['POST'])
@login_required
def admin_ban(id):
    if current_user.role != 'admin':
        abort(403)
    user = User.query.get_or_404(id)
    # Self-ban guard — must fire BEFORE any state change so a misclick can
    # never lock the only admin out of their own account.
    if user.id == current_user.id:
        flash('No puedes banear tu propia cuenta.', 'danger')
        return redirect(url_for('admin_users'))
    user.is_banned = not user.is_banned

    # SECURITY/integrity (audit finding G2.5): a banned author's previously
    # approved work must disappear from every public surface (index, browse,
    # search, leaderboard, recommendations) — all of which filter
    # status=='approved'. Rather than add an is_banned JOIN to each query
    # (easy to forget one), flip the visibility of their approved submissions
    # in lockstep with the ban. On UNban, restore them.
    #   - ban:   approved      -> banned_hidden
    #   - unban: banned_hidden -> approved
    # 'banned_hidden' is distinct from 'rejected' so unban restores ONLY items
    # that were genuinely public before, never anything an admin rejected.
    if user.is_banned:
        Submission.query.filter_by(author_id=user.id, status='approved') \
            .update({'status': 'banned_hidden'}, synchronize_session=False)
    else:
        Submission.query.filter_by(author_id=user.id, status='banned_hidden') \
            .update({'status': 'approved'}, synchronize_session=False)

    db.session.commit()
    flash(
        f'Usuario {"baneado" if user.is_banned else "rehabilitado"}: {user.username}',
        'info',
    )
    return redirect(url_for('admin_users'))


# ---------------------------------------------------------------------------
# Dev server entry point. In production the app is served by a WSGI server
# (gunicorn / PythonAnywhere), NEVER by app.run(). debug follows the config so
# the Werkzeug debugger (arbitrary code exec) is never exposed in production.
# ---------------------------------------------------------------------------
if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'])
