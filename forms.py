# WikiSTEM | Javier Fernando Vega Alamo | CS50x 2026
# This file was drafted with assistance from Claude (Anthropic) inside
# Google Antigravity, working from a specification I authored. All
# architectural decisions, security choices, and final logic were
# reviewed and verified by me before commit.

from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import (StringField, TextAreaField, SelectField, IntegerField,
                     BooleanField, PasswordField)
from wtforms.validators import (DataRequired, Length, Optional, URL,
                                NumberRange, Email, EqualTo, Regexp)

# ---------------------------------------------------------------------------
# Choice constants (§6)
# ---------------------------------------------------------------------------

# Values are stored verbatim in submissions.category and shown raw in the UI, so
# value == Spanish label (the DB holds Spanish; templates print it directly).
RESEARCH_CATEGORIES = [
    ('Biología',                            'Biología'),
    ('Química',                             'Química'),
    ('Física',                              'Física'),
    ('Matemáticas',                         'Matemáticas'),
    ('Informática',                         'Informática'),
    ('Ciencias Ambientales',                'Ciencias Ambientales'),
    ('Historia de la Ciencia & Tecnología', 'Historia de la Ciencia & Tecnología'),
    ('Ética en STEM',                       'Ética en STEM'),
    ('Ingeniería',                          'Ingeniería'),
    ('Economía',                            'Economía'),
    ('Interdisciplinario',                  'Interdisciplinario'),
    ('Otros',                               'Otros'),
]

# value == Spanish label, same rationale as RESEARCH_CATEGORIES. Shared names
# reuse the same value across both tracks so the browse sidebar merges them.
PROJECT_CATEGORIES = [
    ('Informática & Software',              'Informática & Software'),
    ('Robótica & Arduino',                  'Robótica & Arduino'),
    ('Biología & Ciencias de la Vida',      'Biología & Ciencias de la Vida'),
    ('Química',                             'Química'),
    ('Física',                              'Física'),
    ('Matemáticas',                         'Matemáticas'),
    ('Ciencias Ambientales',                'Ciencias Ambientales'),
    ('Ingeniería & Prototipos',             'Ingeniería & Prototipos'),
    ('Historia de la Ciencia & Tecnología', 'Historia de la Ciencia & Tecnología'),
    ('Ética en STEM',                       'Ética en STEM'),
    ('Interdisciplinario',                  'Interdisciplinario'),
    ('Otros',                               'Otros'),
]

SCHOOL_CHOICES = [
    ('Turicara',  'Turicara'),
    ('Vallesol',  'Vallesol'),
    ('UDEP',      'UDEP'),
    ('Other',     'Otro'),
]

# Sentinel value emitted by the SelectField when the user picks "Otro" and
# types a custom school name in the school_other text input. The view code
# substitutes form.school_other.data for form.school.data in that case.
SCHOOL_OTHER_SENTINEL = 'Other'

GRADE_CHOICES = [
    ('1ro Sec',      '1ro Sec'),
    ('2do Sec',      '2do Sec'),
    ('3ro Sec',      '3ro Sec'),
    ('4to Sec',      '4to Sec'),
    ('5to Sec',      '5to Sec'),
    ('Bachillerato', 'Bachillerato'),
    ('Universidad',  'Universidad'),
]

# ---------------------------------------------------------------------------
# Auth forms
# ---------------------------------------------------------------------------

class RegistrationForm(FlaskForm):
    username = StringField('Usuario', validators=[
        DataRequired(),
        Length(min=3, max=32),
        Regexp(r'^[A-Za-z0-9_]+$',
               message='Solo letras, números y guión bajo'),
    ], render_kw={'autocomplete': 'off'})
    email    = StringField('Correo electrónico',
                           validators=[DataRequired(), Email()],
                           render_kw={'autocomplete': 'off'})
    # SECURITY (audit finding G3 — PBKDF2 CPU-DoS): cap password length on both
    # registration and login. PBKDF2 with ~260k iterations is expensive; an
    # unbounded password lets an attacker pin a worker. 128 chars is well above
    # any real passphrase.
    password = PasswordField('Contraseña', validators=[
        DataRequired(),
        Length(min=8, max=128),
    ], render_kw={'autocomplete': 'new-password'})
    confirm  = PasswordField('Confirmar contraseña', validators=[
        DataRequired(),
        EqualTo('password'),
    ], render_kw={'autocomplete': 'new-password'})
    school   = SelectField('Colegio', choices=SCHOOL_CHOICES)
    # Visible only when school == 'Other'. The view replaces school with this
    # value before persisting. Cap matches User.school column length.
    school_other = StringField('¿Cuál es tu colegio?', validators=[
        Optional(),
        Length(max=64),
    ])
    grade    = SelectField('Grado',  choices=GRADE_CHOICES)


class LoginForm(FlaskForm):
    email    = StringField('Correo electrónico',
                           validators=[DataRequired(), Email()],
                           render_kw={'autocomplete': 'off'})
    # SECURITY (audit finding G3): same 128-char cap as RegistrationForm.
    # The constant-time login check (§4.1) always hashes whatever is submitted,
    # so without this cap an attacker can send a multi-MB string to pin a worker.
    password = PasswordField('Contraseña', validators=[
        DataRequired(),
        Length(max=128),
    ], render_kw={'autocomplete': 'off'})


class LogoutForm(FlaskForm):
    """Empty form — exists only to carry the CSRF token for POST logout.
    Injected into every template context via the inject_globals() processor (§6.5)."""
    pass

# ---------------------------------------------------------------------------
# Submission forms
# ---------------------------------------------------------------------------

class ResearchSubmitForm(FlaskForm):
    title         = StringField('Título', validators=[
        DataRequired(),
        Length(min=10, max=120),
    ])
    abstract      = TextAreaField('Resumen (máx. 250 palabras)', validators=[
        DataRequired(),
        Length(min=50, max=2000),
    ])
    category      = SelectField('Categoría', choices=RESEARCH_CATEGORIES)
    ib_type       = SelectField('Tipo', choices=[
        ('Monografía (EE)',                    'Monografía (EE)'),
        ('Evaluación Interna (IA)',            'Evaluación Interna (IA)'),
        ('Artículo de investigación original', 'Artículo de investigación original'),
        ('Otro trabajo académico',             'Otro trabajo académico'),
    ])
    ib_subject    = StringField('Asignatura IB (ej. Biología HL)', validators=[
        Optional(),
        Length(max=60),
    ])
    word_count    = IntegerField('Número de palabras', validators=[
        Optional(),
        NumberRange(min=100, max=20000),
    ])
    academic_year = SelectField('Año académico', choices=[
        ('2026', '2026'),
        ('2025', '2025'),
        ('2024', '2024'),
        ('2023', '2023'),
    ])
    tags          = StringField('Etiquetas (separadas por coma, máx. 5)', validators=[
        Optional(),
        Length(max=120),
    ])
    main_pdf      = FileField('Documento principal (PDF, obligatorio)', validators=[
        FileRequired(),
        FileAllowed(['pdf'], 'Solo PDF'),
    ])
    extra_pdf_1   = FileField('Documento de apoyo 1 (PDF, opcional)', validators=[
        FileAllowed(['pdf']),
    ])
    extra_pdf_2   = FileField('Documento de apoyo 2 (PDF, opcional)', validators=[
        FileAllowed(['pdf']),
    ])
    cover_image   = FileField('Imagen de portada (opcional)', validators=[
        FileAllowed(['png', 'jpg', 'jpeg', 'webp']),
    ])
    external_link = StringField('Enlace externo (DOI, dataset, etc.)', validators=[
        Optional(),
        URL(),
    ])
    integrity_confirmed = BooleanField(
        'Confirmo que este es mi trabajo original y entiendo el '
        'aviso de integridad académica mostrado arriba.',
        validators=[DataRequired(
            message='Debes confirmar la integridad académica para publicar',
        )],
    )


class ProjectSubmitForm(FlaskForm):
    title         = StringField('Título', validators=[
        DataRequired(),
        Length(min=5, max=120),
    ])
    description   = TextAreaField('Descripción (compatible con Markdown)', validators=[
        DataRequired(),
        Length(min=50, max=20000),
    ])
    category      = SelectField('Categoría', choices=PROJECT_CATEGORIES)
    project_type  = SelectField('Tipo de proyecto', choices=[
        ('Arduino / Hardware',          'Arduino / Hardware'),
        ('Software / App / Videojuego', 'Software / App / Videojuego'),
        ('Feria de ciencias',           'Feria de ciencias'),
        ('Prototipo de ingeniería',     'Prototipo de ingeniería'),
        ('Modelo matemático',           'Modelo matemático'),
        ('Otro',                        'Otro'),
    ])
    tags          = StringField('Etiquetas (separadas por coma, máx. 5)', validators=[
        Optional(),
        Length(max=120),
    ])
    cover_image   = FileField('Imagen de portada (obligatoria)', validators=[
        FileRequired(),
        FileAllowed(['png', 'jpg', 'jpeg', 'gif', 'webp']),
    ])
    extra_image_1 = FileField('Imagen adicional 1', validators=[
        FileAllowed(['png', 'jpg', 'jpeg', 'gif', 'webp']),
    ])
    extra_image_2 = FileField('Imagen adicional 2', validators=[
        FileAllowed(['png', 'jpg', 'jpeg', 'gif', 'webp']),
    ])
    extra_image_3 = FileField('Imagen adicional 3', validators=[
        FileAllowed(['png', 'jpg', 'jpeg', 'gif', 'webp']),
    ])
    main_pdf      = FileField('Documento principal (PDF, opcional) — se muestra incrustado', validators=[
        FileAllowed(['pdf'], 'Solo PDF'),
    ])
    document_1    = FileField('Documento 1 (PDF/DOCX/PPTX)', validators=[
        FileAllowed(['pdf', 'docx', 'pptx', 'txt', 'md']),
    ])
    document_2    = FileField('Documento 2', validators=[
        FileAllowed(['pdf', 'docx', 'pptx', 'txt', 'md']),
    ])
    document_3    = FileField('Documento 3', validators=[
        FileAllowed(['pdf', 'docx', 'pptx', 'txt', 'md']),
    ])
    code_snippet  = TextAreaField('Fragmento de código (opcional)', validators=[
        Optional(),
        Length(max=5000),
    ])
    external_link = StringField('Enlace externo (GitHub, YouTube, etc.)', validators=[
        Optional(),
        URL(),
    ])
    integrity_confirmed = BooleanField(
        'Confirmo que este es mi trabajo original y entiendo el '
        'aviso de integridad académica mostrado arriba.',
        validators=[DataRequired(
            message='Debes confirmar la integridad académica para publicar',
        )],
    )

# ---------------------------------------------------------------------------
# Profile form
# ---------------------------------------------------------------------------

class ProfileEditForm(FlaskForm):
    bio          = TextAreaField('Biografía', validators=[
        Optional(),
        Length(max=500),
    ])
    bio_public   = BooleanField('Mostrar biografía públicamente', default=True)
    school       = SelectField('Colegio / Institución', choices=SCHOOL_CHOICES)
    school_other = StringField('¿Cuál es tu colegio?', validators=[
        Optional(),
        Length(max=64),
    ])
    grade        = SelectField('Grado', choices=GRADE_CHOICES)
    skills_tags  = StringField('Habilidades (separadas por coma, máx. 8)', validators=[
        Optional(),
        Length(max=160),
    ])
    linkedin_url = StringField('URL de LinkedIn', validators=[Optional(), URL()])
    github_url   = StringField('URL de GitHub',   validators=[Optional(), URL()])
    avatar       = FileField('Foto de perfil', validators=[
        FileAllowed(['png', 'jpg', 'jpeg']),
    ])
    remove_avatar = BooleanField('Borrar la foto', default=False)

# ---------------------------------------------------------------------------
# Utility / admin forms
# ---------------------------------------------------------------------------

class DeleteSubmissionForm(FlaskForm):
    """Empty form — CSRF token carrier for the submission delete POST."""
    pass


class RejectForm(FlaskForm):
    """Required note when an admin rejects a submission."""
    note = TextAreaField('Motivo del rechazo', validators=[
        DataRequired(),
        Length(min=10, max=500),
    ])


class TwoFactorForm(FlaskForm):
    """Admin hardening (beyond v4 spec): 6-digit TOTP code entered at enrollment
    (/admin/2fa/setup) and at every admin login (/admin/2fa). Regexp pins it to
    exactly six digits so the server never feeds junk to pyotp."""
    code = StringField('Código de verificación', validators=[
        DataRequired(),
        Regexp(r'^\d{6}$', message='Introduce el código de 6 dígitos.'),
    ])
