# WikiSTEM | Javier Fernando Vega Alamo | CS50x 2026
#
# One-off migration: rewrite stored display values from their old English keys
# to the Spanish strings the app now stores and renders directly. Covers the
# four display-only fields — submissions.category / ib_type / project_type and
# users.grade. Internal state keys (track, status) are intentionally untouched.
#
# Safe to re-run: each UPDATE only matches the old English value, so a second
# run finds nothing to change (idempotent). Wrapped in a single transaction.
#
#   python migrate_categories.py

import os
import sqlite3

DB_PATH = os.path.join('instance', 'wikistem.db')

# (table, column, {old_english: new_spanish})
MIGRATIONS = [
    ('submissions', 'category', {
        'Biology':                         'Biología',
        'Chemistry':                       'Química',
        'Physics':                         'Física',
        'Mathematics':                     'Matemáticas',
        'Computer Science':                'Informática',
        'Environmental Science':           'Ciencias Ambientales',
        'History of Science & Technology': 'Historia de la Ciencia & Tecnología',
        'Ethics in STEM':                  'Ética en STEM',
        'Engineering':                     'Ingeniería',
        'Economics':                       'Economía',
        'Interdisciplinary':               'Interdisciplinario',
        'Other':                           'Otros',
        'Computer Science & Software':     'Informática & Software',
        'Robotics & Arduino':              'Robótica & Arduino',
        'Biology & Life Sciences':         'Biología & Ciencias de la Vida',
        'Engineering & Prototyping':       'Ingeniería & Prototipos',
    }),
    ('submissions', 'ib_type', {
        'EE':             'Monografía (EE)',
        'IA':             'Evaluación Interna (IA)',
        'research_paper': 'Artículo de investigación original',
        'other':          'Otro trabajo académico',
    }),
    ('submissions', 'project_type', {
        'arduino':      'Arduino / Hardware',
        'software':     'Software / App / Videojuego',
        'science_fair': 'Feria de ciencias',
        'engineering':  'Prototipo de ingeniería',
        'math_model':   'Modelo matemático',
        'other':        'Otro',
    }),
    ('users', 'grade', {
        'University': 'Universidad',
    }),
]


def main():
    if not os.path.exists(DB_PATH):
        raise SystemExit(f'Database not found at {DB_PATH}. Run init_db.py first.')

    conn = sqlite3.connect(DB_PATH)
    total = 0
    try:
        for table, column, mapping in MIGRATIONS:
            for old, new in mapping.items():
                cur = conn.execute(
                    f'UPDATE {table} SET {column} = ? WHERE {column} = ?',
                    (new, old),
                )
                if cur.rowcount:
                    total += cur.rowcount
                    print(f'  {table}.{column}: {old!r} -> {new!r}  ({cur.rowcount} row(s))')
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    print(f'Done. {total} row(s) updated.' if total else 'Done. Nothing to migrate.')


if __name__ == '__main__':
    main()
