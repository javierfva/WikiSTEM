# WikiSTEM | Javier Fernando Vega Alamo | CS50x 2026
# This file was drafted with assistance from Claude (Anthropic) inside
# Google Antigravity, working from a specification I authored. All
# architectural decisions, security choices, and final logic were
# reviewed and verified by me before commit.

import os
import json
import re
from datetime import datetime, timezone

from google import genai
from google.genai import types
from flask import current_app

from models import db, ModerationLog
from helpers import strip_markdown

# ---------------------------------------------------------------------------
# Gemini setup (§8.1)
# Free quota: 15 req/min, 1,000,000 tokens/day.
#
# Uses the `google-genai` SDK (not the retired `google-generativeai` package).
# Google retired `gemini-1.5-flash` in late 2025 (404 on generateContent).
# `gemini-2.5-flash` is the current free-tier flash model.
# ---------------------------------------------------------------------------

GEMINI_MODEL_NAME = 'gemini-2.5-flash'
client = genai.Client(api_key=os.environ.get('GEMINI_API_KEY', ''))

# Timeouts are passed per-call via HttpOptions (the new SDK takes ms, not s).
REVIEW_TIMEOUT_MS     = 15_000
MODERATION_TIMEOUT_MS = 10_000

# ---------------------------------------------------------------------------
# Shared utility
# ---------------------------------------------------------------------------

def _strip_json_fences(text: str) -> str:
    """Remove markdown code fences Gemini sometimes wraps JSON in."""
    raw = re.sub(r'^```json\s*', '', text.strip())
    raw = re.sub(r'\s*```$',     '', raw.strip())
    return raw

# ---------------------------------------------------------------------------
# AI quality review — prompts and runner (§8.2 / §8.3 / §8.4)
# ---------------------------------------------------------------------------

# NOTE — Output language: JSON KEYS stay in English because they are referenced
# directly by templates and Python (e.g. report.argumentation_score, report.strengths).
# All STRING VALUES and enum labels must be in Spanish — the UI is `lang="es"` and
# the audience is students from Piura. The frontend renders enum values verbatim
# (see templates/partials/ai_panel.html), so they must already be Spanish here.

RESEARCH_SYSTEM_PROMPT = """
Eres un evaluador académico que revisa trabajos de investigación de estudiantes de colegios
IB en Piura, Perú. Los estudiantes tienen entre 15 y 18 años.

Responde EXCLUSIVAMENTE en ESPAÑOL (todos los valores de texto, listas y resúmenes deben
estar en español; las CLAVES del JSON quedan en inglés tal como se piden).
Devuelve SOLO JSON válido — sin bloques de código, sin texto antes o después.
Sé constructivo y motivador: esto es trabajo estudiantil, no investigación arbitrada.
"""

RESEARCH_USER_TEMPLATE = """
Evalúa este trabajo de investigación estudiantil. Devuelve EXACTAMENTE esta estructura JSON
(claves en inglés, valores en español):
{{
  "argumentation_score":  entero 1-10 (claridad de la tesis y del argumento),
  "methodology_score":    entero 1-10 (idoneidad de los métodos usados),
  "structure_score":      entero 1-10 (organización lógica y fluidez),
  "citation_quality":     uno de: "Ninguna" | "Mínima" | "Adecuada" | "Sólida",
  "originality":          uno de: "Derivativa" | "Incremental" | "Original",
  "strengths":            lista de exactamente 3 cadenas en español (máx. 25 palabras cada una),
  "improvements":         lista de exactamente 3 cadenas en español (máx. 25 palabras cada una),
  "suggested_reading":    lista de 1-2 cadenas en español nombrando campos o autores afines,
  "summary":              exactamente 2 oraciones en español: una fortaleza y una mejora
}}

Tipo de trabajo:   {ib_type}
Área temática:     {category}
Asignatura IB:     {ib_subject}
Número de palabras:{word_count}
Título:            {title}
Resumen:           {abstract}
"""

PROJECT_SYSTEM_PROMPT = """
Eres un evaluador de proyectos STEM que revisa construcciones y proyectos de programación de
estudiantes de secundaria en Piura, Perú. Los estudiantes tienen entre 13 y 18 años.

Responde EXCLUSIVAMENTE en ESPAÑOL (todos los valores de texto, listas y resúmenes deben
estar en español; las CLAVES del JSON quedan en inglés tal como se piden).
Devuelve SOLO JSON válido — sin bloques de código, sin texto antes o después.
Sé motivador y específico: señala qué funciona y qué se puede mejorar.
"""

PROJECT_USER_TEMPLATE = """
Evalúa este proyecto STEM estudiantil. Devuelve EXACTAMENTE esta estructura JSON
(claves en inglés, valores en español):
{{
  "originality_score":    entero 1-10,
  "completeness_score":   entero 1-10,
  "technical_depth":      entero 1-10,
  "impact_potential":     uno de: "Bajo" | "Medio" | "Alto",
  "difficulty_level":     uno de: "Principiante" | "Intermedio" | "Avanzado",
  "strengths":            lista de exactamente 3 cadenas en español (máx. 25 palabras cada una),
  "improvements":         lista de exactamente 3 cadenas en español (máx. 25 palabras cada una),
  "next_steps":           lista de exactamente 2 sugerencias accionables en español,
  "similar_fields":       lista de 1-2 disciplinas STEM relacionadas en español,
  "summary":              exactamente 2 oraciones en español: una fortaleza y una mejora
}}

Tipo de proyecto:  {project_type}
Categoría:         {category}
Etiquetas:         {tags}
Título:            {title}
Descripción:       {description}
"""


def run_ai_review(submission):
    """
    Run the AI quality review for an approved submission.
    Track-aware: uses research or project prompt based on submission.track.
    Hard timeout of 15 seconds via request_options.

    Returns a dict parsed from Gemini's JSON response.
    Raises RuntimeError on timeout, API error, or invalid JSON — caller is
    responsible for catching and deciding whether to flash a warning.
    """
    if submission.track == 'research':
        system = RESEARCH_SYSTEM_PROMPT
        user   = RESEARCH_USER_TEMPLATE.format(
            ib_type    = submission.ib_type    or 'unspecified',
            category   = submission.category,
            ib_subject = submission.ib_subject or 'unspecified',
            word_count = submission.word_count or 'unspecified',
            title      = submission.title,
            abstract   = strip_markdown(submission.description_md)[:2000],
        )
    else:
        system = PROJECT_SYSTEM_PROMPT
        user   = PROJECT_USER_TEMPLATE.format(
            project_type = submission.project_type or 'unspecified',
            category     = submission.category,
            tags         = submission.tags         or 'none',
            title        = submission.title,
            description  = strip_markdown(submission.description_md)[:2500],
        )

    try:
        resp = client.models.generate_content(
            model=GEMINI_MODEL_NAME,
            contents=user,
            config=types.GenerateContentConfig(
                system_instruction=system,
                temperature=0.2,
                # 2.5-flash spends internal "thinking" tokens before output, so
                # the v3 budget of 900 truncated mid-JSON. 2048 leaves headroom.
                max_output_tokens=2048,
                # Forces pure JSON — no markdown fences, no preamble. Removes
                # the entire class of "Expecting ',' delimiter" parse failures.
                response_mime_type='application/json',
                http_options=types.HttpOptions(timeout=REVIEW_TIMEOUT_MS),
            ),
        )
        return json.loads(_strip_json_fences(resp.text))
    except json.JSONDecodeError as e:
        raise RuntimeError(f'Gemini returned invalid JSON: {e}')
    except Exception as e:
        raise RuntimeError(f'AI review failed: {e}')

# ---------------------------------------------------------------------------
# AI content moderation — prompt and runner (§9.1 / §9.2)
# ---------------------------------------------------------------------------

MODERATION_SYSTEM = """
Eres moderador de contenido para una plataforma STEM estudiantil dirigida a estudiantes
de 13 a 18 años en Perú.

Responde EXCLUSIVAMENTE en ESPAÑOL: los valores `flag_reason` y los elementos de
`risks_found` deben estar en español (las CLAVES del JSON quedan en inglés).
Devuelve SOLO JSON válido — sin bloques de código, sin texto antes o después.
Sé conservador: marca solo violaciones claras.
El contenido académico (química, biología, armas en contexto histórico o científico) es aceptable.
"""

MODERATION_USER = """
Revisa este trabajo estudiantil por posibles violaciones de política. Devuelve exactamente
este JSON (claves en inglés, valores de texto en español):
{{
  "is_appropriate": booleano,
  "confidence":     entero 1-100,
  "flag_reason":    cadena en español o null,
  "risks_found":    lista de cadenas en español (lista vacía si no hay riesgos)
}}

Marca solo: contenido sexual explícito, instrucciones para dañar personas, discurso de odio,
datos personales reales de otros estudiantes, o spam totalmente fuera de tema.

Pista:      {track}
Título:     {title}
Contenido:  {content}
"""


def run_ai_moderation(submission, log_to_db: bool = True):
    """
    Run AI content moderation against `submission`. Mutates the submission
    in place (status / mod_report / mod_reviewed_at / mod_flag_reason).
    Adds a ModerationLog entry to the SQLAlchemy session unless
    log_to_db=False — the manual re-moderation route (§19.4) passes False
    so the audit trail records only a single 'human_remoderate' entry instead
    of two rows.

    Always returns a dict (never raises). On API failure the submission stays
    'pending' and mod_report records the failure so admin can re-trigger.

    Caller is responsible for db.session.commit().
    """
    content = strip_markdown(submission.description_md or '')[:2000]
    prompt  = MODERATION_USER.format(
        track   = submission.track,
        title   = submission.title,
        content = content,
    )

    try:
        resp = client.models.generate_content(
            model=GEMINI_MODEL_NAME,
            contents=prompt,
            config=types.GenerateContentConfig(
                system_instruction=MODERATION_SYSTEM,
                temperature=0.1,
                # See run_ai_review note — 2.5-flash thinking tokens make the
                # v3 budget of 300 unsafe even for this short JSON schema.
                max_output_tokens=800,
                response_mime_type='application/json',
                http_options=types.HttpOptions(timeout=MODERATION_TIMEOUT_MS),
            ),
        )
        result = json.loads(_strip_json_fences(resp.text))

        submission.mod_report      = json.dumps(result)
        submission.mod_reviewed_at = datetime.now(timezone.utc)

        if not result.get('is_appropriate', True):
            submission.status          = 'flagged'
            submission.mod_flag_reason = result.get('flag_reason', 'AI flagged')
            log_action = 'ai_flagged'
        else:
            log_action = 'ai_approved'

        if log_to_db:
            db.session.add(ModerationLog(
                submission_id = submission.id,
                action        = log_action,
                actor         = 'system',
                note          = result.get('flag_reason'),
            ))
        return result

    except Exception as e:
        current_app.logger.error(
            f'Moderation error on submission {submission.id}: {e}'
        )
        # Submission stays 'pending' — admin will see it in their queue with a
        # "moderation API unavailable" badge and can re-trigger via §19.4.
        failure_record = {
            'is_appropriate': True,
            'confidence':     0,
            'flag_reason':    None,
            'risks_found':    ['Moderation API unavailable — manual review needed'],
        }
        submission.mod_report      = json.dumps(failure_record)
        submission.mod_reviewed_at = datetime.now(timezone.utc)
        if log_to_db:
            db.session.add(ModerationLog(
                submission_id = submission.id,
                action        = 'ai_timeout',
                actor         = 'system',
                note          = str(e)[:200],
            ))
        return failure_record
