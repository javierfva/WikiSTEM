# WikiSTEM | Javier Fernando Vega Alamo | CS50x 2026
# This file was drafted with assistance from Claude (Anthropic) inside
# Google Antigravity, working from a specification I authored. All
# architectural decisions, security choices, and final logic were
# reviewed and verified by me before commit.

import os
import re
import uuid
import json
import smtplib
import hashlib
import unicodedata
from io import BytesIO
from email.message import EmailMessage

import pyotp
from cryptography.fernet import Fernet, InvalidToken
from PIL import Image, ImageOps
import fitz   # PyMuPDF
import magic  # python-magic / python-magic-bin
import markdown as _md
import bleach
from slugify import slugify
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from flask import current_app

# ---------------------------------------------------------------------------
# Upload validation constants (§4.3)
# ---------------------------------------------------------------------------

ALLOWED_IMG_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
ALLOWED_DOC_EXT = {'pdf', 'docx', 'pptx', 'txt', 'md'}

# Expected libmagic MIME types per extension — validated against actual file bytes.
# Older libmagic may report DOCX/PPTX as application/zip (both valid).
IMG_MIME = {
    'png':  {'image/png'},
    'jpg':  {'image/jpeg'},
    'jpeg': {'image/jpeg'},
    'gif':  {'image/gif'},
    'webp': {'image/webp'},
}
DOC_MIME = {
    'pdf':  {'application/pdf'},
    'docx': {'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
             'application/zip'},
    'pptx': {'application/vnd.openxmlformats-officedocument.presentationml.presentation',
             'application/zip'},
    'txt':  {'text/plain'},
    'md':   {'text/plain', 'text/markdown'},
}

MAX_IMG_MB = 5
MAX_DOC_MB = 20

# SECURITY (audit finding C3 — decompression-bomb DoS): the MAX_IMG_MB cap is
# on the COMPRESSED upload bytes. A 5 MB PNG can decode to gigabytes of RAM.
# We cap decoded pixel count and each dimension. Pillow raises
# Image.DecompressionBombError above MAX_IMAGE_PIXELS.
MAX_IMAGE_PIXELS    = 40_000_000   # 40 MP
MAX_IMAGE_DIMENSION = 12_000       # px per side hard cap
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

# ---------------------------------------------------------------------------
# PII encryption — Fernet AES-128-CBC + HMAC-SHA256 (§4.2)
# ---------------------------------------------------------------------------

def get_fernet() -> Fernet:
    return Fernet(os.environ['ENCRYPTION_KEY'].encode())


def encrypt(text: str) -> str:
    if not text:
        return text
    return get_fernet().encrypt(text.encode()).decode()


def decrypt(cipher: str) -> str:
    if not cipher:
        return cipher
    return get_fernet().decrypt(cipher.encode()).decode()


def email_hash(email: str) -> str:
    """SHA-256 of lowercased, stripped email — stored for login lookups."""
    if not email:
        return ''
    return hashlib.sha256(email.lower().strip().encode()).hexdigest()

# ---------------------------------------------------------------------------
# Email-verification tokens + SMTP delivery (registration only — deviates from
# Backend Spec §2, which excluded Flask-Mail; owner-approved).
# ---------------------------------------------------------------------------
# Sign-up is verify-then-create: the pending registration is carried INSIDE a
# Fernet-encrypted, time-limited token that is emailed to the user. No row is
# written to the database until they click the link, so there is no "unverified"
# state and no schema change. Fernet provides confidentiality + integrity + TTL
# in one primitive, and its output is URL-safe base64, so the token rides safely
# in the verification link's path segment.

EMAIL_TOKEN_MAX_AGE = 24 * 60 * 60   # 24 hours


def make_pending_registration_token(data: dict) -> str:
    """Encrypt a pending-registration payload into a URL-safe activation token."""
    return get_fernet().encrypt(json.dumps(data).encode()).decode()


def read_pending_registration_token(token, max_age=EMAIL_TOKEN_MAX_AGE):
    """Decrypt a pending-registration token back into its payload dict.

    Returns None if the token is missing, tampered, malformed, or older than
    `max_age` seconds — Fernet's ttl raises InvalidToken in every such case, so
    expiry and forgery collapse into one safe failure path.
    """
    if not token:
        return None
    try:
        raw = get_fernet().decrypt(token.encode(), ttl=max_age)
        return json.loads(raw.decode())
    except (InvalidToken, ValueError, UnicodeDecodeError):
        return None


def send_email(to_addr: str, subject: str, body_text: str, body_html=None) -> None:
    """Send an email over SMTP using the MAIL_* environment settings.

    Reads config directly from os.environ (same pattern as get_fernet). Raises on
    any missing setting or SMTP/connection error so the caller decides how to
    surface the failure to the user.
    """
    server   = os.environ['MAIL_SERVER']
    port     = int(os.environ.get('MAIL_PORT', 587))
    use_tls  = os.environ.get('MAIL_USE_TLS', '1') not in ('0', 'false', 'False', '')
    username = os.environ['MAIL_USERNAME']
    password = os.environ['MAIL_PASSWORD']
    sender   = os.environ.get('MAIL_DEFAULT_SENDER', username)

    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From']    = sender
    msg['To']      = to_addr
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype='html')

    with smtplib.SMTP(server, port, timeout=15) as smtp:
        if use_tls:
            smtp.starttls()
        smtp.login(username, password)
        smtp.send_message(msg)


def send_verification_email(to_addr: str, verify_url: str) -> None:
    """Email the 24-hour account-activation link to a pending registrant."""
    subject = 'Verifica tu cuenta de WikiSTEM'
    body_text = (
        '¡Hola!\n\n'
        'Gracias por registrarte en WikiSTEM. Para activar tu cuenta, abre el '
        'siguiente enlace (válido por 24 horas):\n\n'
        f'{verify_url}\n\n'
        'Si no creaste esta cuenta, ignora este mensaje: no se guardará ningún '
        'dato hasta que confirmes.\n\n'
        '— El equipo de WikiSTEM'
    )
    body_html = (
        '<p>¡Hola!</p>'
        '<p>Gracias por registrarte en <strong>WikiSTEM</strong>. Para activar '
        'tu cuenta, abre el siguiente enlace (válido por 24 horas):</p>'
        f'<p><a href="{verify_url}">Activar mi cuenta</a></p>'
        '<p>Si no creaste esta cuenta, ignora este mensaje: no se guardará '
        'ningún dato hasta que confirmes.</p>'
        '<p>— El equipo de WikiSTEM</p>'
    )
    send_email(to_addr, subject, body_text, body_html)

# ---------------------------------------------------------------------------
# Admin hardening (owner-approved, beyond v4 spec): TOTP helpers — thin wrappers
# over pyotp so the dependency lives in one place.
# ---------------------------------------------------------------------------

def totp_provisioning_uri(secret: str, account_name: str,
                          issuer: str = 'WikiSTEM') -> str:
    """otpauth:// URI for `secret`, encoded into the enrollment QR code."""
    return pyotp.TOTP(secret).provisioning_uri(name=account_name,
                                               issuer_name=issuer)


def totp_verify(secret: str, code: str) -> bool:
    """True if `code` is a valid current TOTP for `secret`.

    valid_window=1 accepts the immediately previous/next 30 s step to tolerate
    minor clock skew between the server and the authenticator app.
    """
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=1)

# ---------------------------------------------------------------------------
# Markdown rendering (§16.2)
# ---------------------------------------------------------------------------

ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'u', 'code', 'pre',
    'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'ul', 'ol', 'li',
    'blockquote',
    'a',
    'hr',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
    'img',
]
ALLOWED_ATTRS = {
    'a':   ['href', 'title', 'rel'],
    'img': ['src', 'alt', 'title'],
    '*':   ['class'],
}
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']


def render_markdown(text: str) -> str:
    """Convert Markdown to safe sanitised HTML (explicit Bleach allowlist)."""
    if not text:
        return ''
    raw_html = _md.markdown(
        text,
        extensions=['fenced_code', 'tables', 'sane_lists', 'nl2br'],
        output_format='html5',
    )
    cleaned = bleach.clean(
        raw_html,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )
    cleaned = bleach.linkify(
        cleaned,
        callbacks=[
            lambda attrs, new: {**attrs, (None, 'rel'): 'nofollow noopener'}
        ],
    )
    return cleaned


def strip_markdown(text: str) -> str:
    """Plain text from Markdown — used to feed AI review/moderation."""
    if not text:
        return ''
    out = re.sub(r'`{1,3}[^`]*`{1,3}', ' ', text)
    out = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', out)
    out = re.sub(r'[*_#>~|]', '', out)
    out = re.sub(r'\s+', ' ', out).strip()
    return out

# ---------------------------------------------------------------------------
# Slug helpers (§16.3)
# ---------------------------------------------------------------------------

def make_unique_slug(title: str) -> str:
    """Return a URL-safe base slug from title. Caller handles collisions."""
    return slugify(title, max_length=80) or 'untitled'


def _try_commit_submission_with_slug(submission, base_slug: str) -> str:
    """Attempt base, base-2, base-3 … until commit succeeds (max 50)."""
    # Import db here to avoid circular import at module load time.
    from models import db
    for i in range(50):
        slug = base_slug if i == 0 else f'{base_slug}-{i + 1}'
        submission.slug = slug
        try:
            db.session.add(submission)
            db.session.commit()
            return slug
        except IntegrityError:
            db.session.rollback()
            continue
    raise RuntimeError(
        f'Could not find a unique slug after 50 attempts for: {base_slug}'
    )

# ---------------------------------------------------------------------------
# Tag sanitiser (§16.4)
# ---------------------------------------------------------------------------

def sanitize_tags(text: str, max_tags: int = 5, max_len: int = 20) -> str:
    """Comma-separated string in → cleaned, deduplicated, capped string out."""
    if not text:
        return ''
    seen = []
    for raw_tag in text.split(','):
        t = raw_tag.strip().lower()[:max_len]
        if t and t not in seen:
            seen.append(t)
        if len(seen) >= max_tags:
            break
    return ','.join(seen)

# ---------------------------------------------------------------------------
# FTS5 query sanitiser (§12)
# ---------------------------------------------------------------------------

_HYPHENATED_TOKEN        = re.compile(r'^\w[\w]*(?:-\w[\w]*)+$')
_FTS5_SPECIAL_NON_HYPHEN = re.compile(r'[^\w\s\-]')


def sanitise_fts_query(q: str) -> str:
    """
    Convert free-text user input into a safe FTS5 MATCH expression.

    Hyphenated technical terms (ESP-32, pH-level, 555-timer) are emitted as
    FTS5 phrase queries ("ESP 32") because the unicode61 tokenizer splits on
    hyphens at index time too, making adjacent tokens the correct match.
    All other FTS5 operators (", *, (, :, reserved words) are stripped.
    Returns '' if the entire input reduces to operators/punctuation.
    """
    cleaned = _FTS5_SPECIAL_NON_HYPHEN.sub(' ', q)
    tokens  = [t for t in cleaned.split() if t]

    parts = []
    for token in tokens:
        token = token.strip('-')
        if not token:
            continue
        if _HYPHENATED_TOKEN.match(token):
            phrase_body = token.replace('-', ' ')
            parts.append(f'"{phrase_body}"')
        else:
            safe = token.replace('-', ' ').strip()
            if safe:
                parts.append(f'"{safe}"*')

    return ' '.join(parts)


# ---------------------------------------------------------------------------
# Fuzzy search fallback (app-level; no DB schema change)
#
# FTS5 handles exact / prefix / accent-folded matching, but it cannot tolerate
# real misspellings ("karna" -> "karina"). When the FTS + category pass returns
# nothing, the search route falls back to this rapidfuzz scan over the existing
# title/tags/category columns. The corpus is small (a school project), so a
# full in-Python scan of approved rows is perfectly fine.
# ---------------------------------------------------------------------------

_COMBINING = re.compile(r'[̀-ͯ]')


def _strip_accents(text: str) -> str:
    """Fold accents for case/diacritic-insensitive comparison.

    'investigación' -> 'investigacion', 'Niño' -> 'nino'. Used so the fuzzy
    pass matches regardless of accents (the FTS index already folds Latin
    vowels via its default tokenizer; this covers ñ and the fuzzy haystack).
    """
    if not text:
        return ''
    decomposed = unicodedata.normalize('NFKD', text)
    return _COMBINING.sub('', decomposed)


def fuzzy_search(session, q: str, track: str = None,
                 limit: int = 30, threshold: int = 60) -> list:
    """Return approved submission ids fuzzily matching `q`, best score first.

    Scans (id, title, tags, category) for approved submissions and scores each
    against the accent-folded query with rapidfuzz WRatio. Only candidates at
    or above `threshold` are kept. Returns [] if rapidfuzz is unavailable, so a
    missing wheel degrades search to FTS+category rather than crashing.
    """
    needle = _strip_accents((q or '').strip().lower())
    if not needle:
        return []

    try:
        from rapidfuzz import fuzz
    except ImportError:
        return []

    sql = ("SELECT id, title, tags, category FROM submissions "
           "WHERE status = 'approved'")
    params = {}
    if track in ('research', 'project'):
        sql += ' AND track = :track'
        params['track'] = track

    # PERF (audit finding P2): the rapidfuzz pass scans these rows in Python, so bound
    # the set to the most recent N approved rows rather than the whole (growing) table.
    # Fuzzy is only a fallback when exact FTS + category found nothing, so capping the
    # haystack to recent items keeps it useful without an unbounded scan.
    sql += ' ORDER BY id DESC LIMIT 500'

    rows = session.execute(text(sql), params).fetchall()
    if not rows:
        return []

    # Score the query against EACH field separately and keep the best score
    # (audit/QA finding): concatenating title+tags+category into one haystack and
    # scoring that with WRatio triggers WRatio's length penalty — a 1-char typo of a
    # title ('arduuino') scores ~80 against the title alone but only ~56 against the
    # long combined string, dropping under the cutoff so the fuzzy fallback never
    # fired. Taking the per-field max restores typo tolerance without lowering the bar.
    scored = []
    for row in rows:
        fields = [_strip_accents((field or '').lower())
                  for field in (row.title, row.tags, row.category)]
        field_scores = [fuzz.WRatio(needle, field) for field in fields if field]
        if not field_scores:
            continue
        score = max(field_scores)
        if score >= threshold:
            scored.append((score, row.id))

    # Best score first; cap to `limit`.
    scored.sort(key=lambda pair: pair[0], reverse=True)
    return [submission_id for _score, submission_id in scored[:limit]]


# ---------------------------------------------------------------------------
# File upload helpers (§4.3)
# ---------------------------------------------------------------------------

def _check_mime(raw_bytes: bytes, allowed_mimes: set, file_kind: str) -> None:
    """Raise ValueError if libmagic detection does not match any allowed MIME."""
    detected = magic.from_buffer(raw_bytes, mime=True)
    if detected not in allowed_mimes:
        raise ValueError(
            f'El archivo no es un {file_kind} válido (detectado: {detected})'
        )


def secure_image_upload(file_storage, folder: str, max_px: int = 1920) -> str:
    """
    Validate, EXIF-transpose, resize and save an uploaded image.
    Returns the saved UUID filename on success; raises ValueError on any failure.
    """
    ext = file_storage.filename.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED_IMG_EXT:
        raise ValueError('Tipo de imagen no permitido')

    raw = file_storage.read()
    if len(raw) > MAX_IMG_MB * 1024 ** 2:
        raise ValueError(f'El tamaño máximo de imagen es {MAX_IMG_MB} MB')

    # Magic-byte validation via libmagic.
    _check_mime(raw, IMG_MIME[ext], 'image')

    # Structural validation via Pillow.
    # SECURITY (audit finding C3): DecompressionBombError must be caught
    # first and specifically — it is a subclass of OSError in Pillow 10+.
    # Image.open() itself can raise it if the image header signals enormous
    # dimensions, so both open() and verify() are inside the try block.
    try:
        img = Image.open(BytesIO(raw))
        img.verify()
        # verify() leaves the file object exhausted and the image in an
        # unusable state — re-open the raw bytes to get a workable object.
        img = Image.open(BytesIO(raw))
    except Image.DecompressionBombError:
        raise ValueError(
            'La imagen es demasiado grande (posible bomba de descompresión)'
        )
    except Exception:
        raise ValueError('Imagen inválida o corrupta')

    # Dimension cap — independent of the global pixel cap.
    if img.width > MAX_IMAGE_DIMENSION or img.height > MAX_IMAGE_DIMENSION:
        raise ValueError(
            f'Dimensiones máximas: {MAX_IMAGE_DIMENSION}×{MAX_IMAGE_DIMENSION} px'
        )

    # v4 fix: respect EXIF orientation so portrait phone photos are not
    # stored rotated 90°. exif_transpose() rotates pixel data and strips tag.
    img = ImageOps.exif_transpose(img)

    img.thumbnail((max_px, max_px))

    fname = uuid.uuid4().hex + '.' + ext
    img.save(os.path.join(folder, fname))
    return fname


def secure_doc_upload(file_storage, folder: str) -> str:
    """
    Validate and save an uploaded document.
    Returns the saved UUID filename on success; raises ValueError on any failure.
    """
    ext = file_storage.filename.rsplit('.', 1)[-1].lower()
    if ext not in ALLOWED_DOC_EXT:
        raise ValueError('Tipo de documento no permitido')

    raw = file_storage.read()
    if len(raw) > MAX_DOC_MB * 1024 ** 2:
        raise ValueError(f'El tamaño máximo de documento es {MAX_DOC_MB} MB')

    # Magic-byte validation for ALL document types — not just PDFs.
    _check_mime(raw, DOC_MIME[ext], 'document')

    # Structural validation for PDFs only.
    # v4 fix: catch ONLY fitz.FileDataError (the actual parse-failure exception).
    # A broad except Exception would also catch our own ValueError from the
    # page_count check below, hiding the specific reason from the user.
    if ext == 'pdf':
        try:
            doc = fitz.open(stream=raw, filetype='pdf')
        except fitz.FileDataError:
            raise ValueError('PDF inválido o corrupto')
        if doc.page_count == 0:
            raise ValueError('El PDF no tiene páginas')

    fname = uuid.uuid4().hex + '.' + ext
    with open(os.path.join(folder, fname), 'wb') as f:
        f.write(raw)
    return fname

# ---------------------------------------------------------------------------
# File cleanup helper (§18 / audit finding G1)
# ---------------------------------------------------------------------------

def _delete_file_if_exists(folder: str, filename: str) -> None:
    """
    Delete a single upload file. Routes 'documents' to instance/uploads/
    (outside static/) and everything else to UPLOAD_FOLDER (static/uploads/).

    SECURITY (audit finding G1 — orphaned-document storage leak): v4 moved
    user documents out of static/ into instance/uploads/documents/ so they
    cannot be served inline. The cleanup path MUST follow them there, otherwise
    os.remove() targets the wrong directory and leaves the real file orphaned.
    """
    if not filename:
        return

    if folder == 'documents':
        base = os.path.join(current_app.instance_path, 'uploads')
    else:
        base = current_app.config['UPLOAD_FOLDER']

    # Defence-in-depth: never let a crafted filename escape the intended dir.
    safe_name = os.path.basename(filename)
    path = os.path.join(base, folder, safe_name)

    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError as e:
            current_app.logger.warning(f'Could not delete {path}: {e}')
