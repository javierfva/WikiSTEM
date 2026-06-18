# WikiSTEM | Javier Fernando Vega Alamo | CS50x 2026
# This file was drafted with assistance from Claude (Anthropic) inside
# Google Antigravity, working from a specification I authored. All
# architectural decisions, security choices, and final logic were
# reviewed and verified by me before commit.

from typing import NamedTuple


class Pixel(NamedTuple):
    x:    int
    y:    int
    fill: str   # hex colour string, e.g. '#F0F0F0' or '#F5E642'


# ---------------------------------------------------------------------------
# Glyph data (§25.3 / §25.4)
#
# Each entry: (width, [(row, col), ...]) where the list enumerates ON pixels.
# Width is the design-pixel width of the glyph itself; the inter-glyph gap of
# 1 design pixel is added by the renderers below, NOT stored here.
#
# v4 updates (aligned with frontend Appendix C):
#   N  — doubled diagonal: rows 1-2 are (col 0,1) and rows 4-5 are (col 3,4)
#   G  — closed top-right and bottom: row 0 and row 6 include col 4
#   _k — thicker descender: row 5 gains (5,1) giving (5,0),(5,1),(5,3)
# ---------------------------------------------------------------------------

_GLYPH_DATA: dict[str, tuple[int, list[tuple[int, int]]]] = {

    # -------------------------------------------------------------------------
    # Uppercase letters (A–Z)
    # All width 5 except M and W which are width 7.
    # -------------------------------------------------------------------------
    'A': (5, [
        (0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,0),(3,1),(3,2),(3,3),(3,4),
        (4,0),(4,4),
        (5,0),(5,4),
        (6,0),(6,4),
    ]),
    'B': (5, [
        (0,0),(0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,0),(3,1),(3,2),(3,3),
        (4,0),(4,4),
        (5,0),(5,4),
        (6,0),(6,1),(6,2),(6,3),
    ]),
    'C': (5, [
        (0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,0),
        (3,0),
        (4,0),
        (5,0),(5,4),
        (6,1),(6,2),(6,3),
    ]),
    'D': (5, [
        (0,0),(0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,0),(3,4),
        (4,0),(4,4),
        (5,0),(5,4),
        (6,0),(6,1),(6,2),(6,3),
    ]),
    'E': (5, [
        (0,0),(0,1),(0,2),(0,3),(0,4),
        (1,0),
        (2,0),
        (3,0),(3,1),(3,2),(3,3),
        (4,0),
        (5,0),
        (6,0),(6,1),(6,2),(6,3),(6,4),
    ]),
    'F': (5, [
        (0,0),(0,1),(0,2),(0,3),(0,4),
        (1,0),
        (2,0),
        (3,0),(3,1),(3,2),(3,3),
        (4,0),
        (5,0),
        (6,0),
    ]),
    # v4 — closed top-right (.1111) and bottom (.1111)
    'G': (5, [
        (0,1),(0,2),(0,3),(0,4),
        (1,0),
        (2,0),
        (3,0),(3,3),(3,4),
        (4,0),(4,4),
        (5,0),(5,4),
        (6,1),(6,2),(6,3),(6,4),
    ]),
    'H': (5, [
        (0,0),(0,4),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,0),(3,1),(3,2),(3,3),(3,4),
        (4,0),(4,4),
        (5,0),(5,4),
        (6,0),(6,4),
    ]),
    'I': (3, [
        (0,0),(0,1),(0,2),
        (1,1),
        (2,1),
        (3,1),
        (4,1),
        (5,1),
        (6,0),(6,1),(6,2),
    ]),
    'J': (5, [
        (0,2),(0,3),(0,4),
        (1,3),
        (2,3),
        (3,3),
        (4,0),(4,3),
        (5,0),(5,3),
        (6,1),(6,2),
    ]),
    'K': (5, [
        (0,0),(0,4),
        (1,0),(1,3),
        (2,0),(2,2),
        (3,0),(3,1),
        (4,0),(4,2),
        (5,0),(5,3),
        (6,0),(6,4),
    ]),
    'L': (5, [
        (0,0),
        (1,0),
        (2,0),
        (3,0),
        (4,0),
        (5,0),
        (6,0),(6,1),(6,2),(6,3),(6,4),
    ]),
    'M': (7, [
        (0,0),(0,6),
        (1,0),(1,1),(1,5),(1,6),
        (2,0),(2,2),(2,4),(2,6),
        (3,0),(3,3),(3,6),
        (4,0),(4,6),
        (5,0),(5,6),
        (6,0),(6,6),
    ]),
    # v4 — doubled diagonal: rows 1-2 widen left stroke, rows 4-5 widen right stroke
    'N': (5, [
        (0,0),(0,4),
        (1,0),(1,1),(1,4),
        (2,0),(2,1),(2,4),
        (3,0),(3,2),(3,4),
        (4,0),(4,3),(4,4),
        (5,0),(5,3),(5,4),
        (6,0),(6,4),
    ]),
    'O': (5, [
        (0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,0),(3,4),
        (4,0),(4,4),
        (5,0),(5,4),
        (6,1),(6,2),(6,3),
    ]),
    'P': (5, [
        (0,0),(0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,0),(3,1),(3,2),(3,3),
        (4,0),
        (5,0),
        (6,0),
    ]),
    'Q': (5, [
        (0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,0),(3,4),
        (4,0),(4,2),(4,4),
        (5,0),(5,3),(5,4),
        (6,1),(6,2),(6,4),
    ]),
    'R': (5, [
        (0,0),(0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,0),(3,1),(3,2),(3,3),
        (4,0),(4,2),
        (5,0),(5,3),
        (6,0),(6,4),
    ]),
    'S': (5, [
        (0,1),(0,2),(0,3),(0,4),
        (1,0),
        (2,0),
        (3,1),(3,2),(3,3),
        (4,4),
        (5,4),
        (6,0),(6,1),(6,2),(6,3),
    ]),
    'T': (5, [
        (0,0),(0,1),(0,2),(0,3),(0,4),
        (1,2),
        (2,2),
        (3,2),
        (4,2),
        (5,2),
        (6,2),
    ]),
    'U': (5, [
        (0,0),(0,4),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,0),(3,4),
        (4,0),(4,4),
        (5,0),(5,4),
        (6,1),(6,2),(6,3),
    ]),
    'V': (5, [
        (0,0),(0,4),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,0),(3,4),
        (4,1),(4,3),
        (5,1),(5,3),
        (6,2),
    ]),
    'W': (7, [
        (0,0),(0,6),
        (1,0),(1,6),
        (2,0),(2,6),
        (3,0),(3,2),(3,4),(3,6),
        (4,0),(4,2),(4,4),(4,6),
        (5,1),(5,5),
        (6,2),(6,4),
    ]),
    'X': (5, [
        (0,0),(0,4),
        (1,0),(1,4),
        (2,1),(2,3),
        (3,2),
        (4,1),(4,3),
        (5,0),(5,4),
        (6,0),(6,4),
    ]),
    'Y': (5, [
        (0,0),(0,4),
        (1,0),(1,4),
        (2,1),(2,3),
        (3,2),
        (4,2),
        (5,2),
        (6,2),
    ]),
    'Z': (5, [
        (0,0),(0,1),(0,2),(0,3),(0,4),
        (1,4),
        (2,3),
        (3,2),
        (4,1),
        (5,0),
        (6,0),(6,1),(6,2),(6,3),(6,4),
    ]),

    # -------------------------------------------------------------------------
    # Digits (0–9)
    # All width 5 except 1 which is width 3.
    # -------------------------------------------------------------------------
    '0': (5, [
        (0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,0),(2,3),(2,4),
        (3,0),(3,2),(3,4),
        (4,0),(4,1),(4,4),
        (5,0),(5,4),
        (6,1),(6,2),(6,3),
    ]),
    '1': (3, [
        (0,1),
        (1,0),(1,1),
        (2,1),
        (3,1),
        (4,1),
        (5,1),
        (6,0),(6,1),(6,2),
    ]),
    '2': (5, [
        (0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,4),
        (3,3),
        (4,2),
        (5,1),
        (6,0),(6,1),(6,2),(6,3),(6,4),
    ]),
    '3': (5, [
        (0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,4),
        (3,2),(3,3),
        (4,4),
        (5,0),(5,4),
        (6,1),(6,2),(6,3),
    ]),
    '4': (5, [
        (0,3),
        (1,2),(1,3),
        (2,1),(2,3),
        (3,0),(3,3),
        (4,0),(4,1),(4,2),(4,3),(4,4),
        (5,3),
        (6,3),
    ]),
    '5': (5, [
        (0,0),(0,1),(0,2),(0,3),(0,4),
        (1,0),
        (2,0),
        (3,0),(3,1),(3,2),(3,3),
        (4,4),
        (5,4),
        (6,0),(6,1),(6,2),(6,3),
    ]),
    '6': (5, [
        (0,1),(0,2),(0,3),
        (1,0),
        (2,0),
        (3,0),(3,1),(3,2),(3,3),
        (4,0),(4,4),
        (5,0),(5,4),
        (6,1),(6,2),(6,3),
    ]),
    '7': (5, [
        (0,0),(0,1),(0,2),(0,3),(0,4),
        (1,4),
        (2,3),
        (3,2),
        (4,2),
        (5,2),
        (6,2),
    ]),
    '8': (5, [
        (0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,1),(3,2),(3,3),
        (4,0),(4,4),
        (5,0),(5,4),
        (6,1),(6,2),(6,3),
    ]),
    '9': (5, [
        (0,1),(0,2),(0,3),
        (1,0),(1,4),
        (2,0),(2,4),
        (3,1),(3,2),(3,3),(3,4),
        (4,4),
        (5,4),
        (6,1),(6,2),(6,3),
    ]),

    # -------------------------------------------------------------------------
    # Punctuation
    # -------------------------------------------------------------------------
    ' ': (3, []),
    '.': (2, [(5,0),(6,0)]),
    '-': (4, [(3,0),(3,1),(3,2),(3,3)]),
    '/': (4, [(0,3),(1,3),(2,2),(3,2),(4,1),(5,1),(6,0)]),
    '·': (2, [(3,0),(3,1)]),

    # -------------------------------------------------------------------------
    # Spanish accented uppercase letters (Á É Í Ó Ú Ñ) — 9 rows tall
    # Rows 0-1 hold a 2-pixel diacritic (diagonal acute / two-row tilde); rows
    # 2-8 hold the full unaccented uppercase letter, exactly matching the base
    # glyph shifted down by 2. When any accented glyph appears in a string,
    # pixel_text_pixels() shifts every unaccented glyph down by 2 too so the
    # baseline stays aligned. The macro then uses pixel_text_height() to grow
    # the SVG viewBox from 7 to 9.
    # -------------------------------------------------------------------------
    'Á': (5, [
        (0,3),
        (1,2),
        (2,1),(2,2),(2,3),
        (3,0),(3,4),
        (4,0),(4,4),
        (5,0),(5,1),(5,2),(5,3),(5,4),
        (6,0),(6,4),
        (7,0),(7,4),
        (8,0),(8,4),
    ]),
    'É': (5, [
        (0,3),
        (1,2),
        (2,0),(2,1),(2,2),(2,3),(2,4),
        (3,0),
        (4,0),
        (5,0),(5,1),(5,2),(5,3),
        (6,0),
        (7,0),
        (8,0),(8,1),(8,2),(8,3),(8,4),
    ]),
    'Í': (3, [
        (0,2),
        (1,1),
        (2,0),(2,1),(2,2),
        (3,1),
        (4,1),
        (5,1),
        (6,1),
        (7,1),
        (8,0),(8,1),(8,2),
    ]),
    'Ó': (5, [
        (0,3),
        (1,2),
        (2,1),(2,2),(2,3),
        (3,0),(3,4),
        (4,0),(4,4),
        (5,0),(5,4),
        (6,0),(6,4),
        (7,0),(7,4),
        (8,1),(8,2),(8,3),
    ]),
    'Ú': (5, [
        (0,3),
        (1,2),
        (2,0),(2,4),
        (3,0),(3,4),
        (4,0),(4,4),
        (5,0),(5,4),
        (6,0),(6,4),
        (7,0),(7,4),
        (8,1),(8,2),(8,3),
    ]),
    # Ñ — two-row wavy tilde (rows 0-1); full N (per spec §C.2) on rows 2-8.
    'Ñ': (5, [
        (0,1),(0,2),(0,4),
        (1,0),(1,2),(1,3),
        (2,0),(2,4),
        (3,0),(3,1),(3,4),
        (4,0),(4,1),(4,4),
        (5,0),(5,2),(5,4),
        (6,0),(6,3),(6,4),
        (7,0),(7,3),(7,4),
        (8,0),(8,4),
    ]),

    # -------------------------------------------------------------------------
    # Wordmark-only lowercase glyphs (NOT in _TEXT_CHARSET — §25.3)
    # These are only accessible via pixel_wordmark_pixels().
    # -------------------------------------------------------------------------
    # _i — width 3. Effective glyph width is 3 design pixels (the surrounding
    # empty columns are part of the inter-glyph gap in the wordmark, not the
    # glyph itself), which yields the correct total wordmark width of 47.
    '_i': (3, [
        (0,1),
        (2,0),(2,1),
        (3,1),
        (4,1),
        (5,1),
        (6,0),(6,1),(6,2),
    ]),
    # _k — width 5. v4: row 5 gains (5,1) so the descender is thicker at base,
    # matching frontend Appendix C.5. v3 had only (5,0) and (5,3).
    '_k': (5, [
        (0,0),
        (1,0),
        (2,0),(2,4),
        (3,0),(3,3),
        (4,0),(4,2),
        (5,0),(5,1),(5,3),
        (6,0),(6,4),
    ]),
}

# Characters accessible through pixel_text_pixels() and pixel_text_width().
# Wordmark-only glyphs (_i, _k) are deliberately excluded.
_TEXT_CHARSET   = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .-/·ÁÉÍÓÚÑ')
_ACCENTED       = set('ÁÉÍÓÚÑ')
_INTER_GLYPH_GAP = 1
_BASE_HEIGHT    = 7    # unaccented glyphs span rows 0-6
_ACCENT_HEIGHT  = 9    # accented strings span rows 0-8 (2-row diacritic + letter)
_ACCENT_SHIFT   = 2    # rows to shift unaccented glyphs in mixed-accent text


# ---------------------------------------------------------------------------
# Public functions (§25.5)
# ---------------------------------------------------------------------------

def pixel_wordmark_pixels(wiki_color: str, stem_color: str) -> list:
    """
    Return Pixel tuples for the WikiSTEM pixel-art wordmark.

    Sequence: W · _i · _k · _i · S · T · E · M
    Glyph widths: 7 + 3 + 5 + 3 + 5 + 5 + 5 + 7 = 40 design pixels
    Plus 7 inter-glyph gaps of 1 = 47 total width (viewBox fits in 47).
    """
    sequence = [
        ('W',  wiki_color),
        ('_i', wiki_color),
        ('_k', wiki_color),
        ('_i', wiki_color),
        ('S',  stem_color),
        ('T',  stem_color),
        ('E',  stem_color),
        ('M',  stem_color),
    ]
    pixels: list = []
    cursor_x = 0
    for glyph_key, color in sequence:
        width, on_pixels = _GLYPH_DATA[glyph_key]
        for (row, col) in on_pixels:
            pixels.append(Pixel(x=cursor_x + col, y=row, fill=color))
        cursor_x += width + _INTER_GLYPH_GAP
    return pixels


def pixel_text_pixels(text: str) -> list:
    """
    Return Pixel tuples for a generic uppercase string.
    Unsupported characters are silently skipped. NEVER raises.
    fill='' because templates supply the colour via CSS class.

    Accent handling: accented glyphs (Á É Í Ó Ú Ñ) store the diacritic at row 0
    and the letter body at rows 1-7. When the string contains at least one
    accented char, every unaccented glyph is shifted down by 1 so the baselines
    line up. The caller must use pixel_text_height(text) for the SVG viewBox so
    the extra row of headroom is reserved.
    """
    text_upper = text.upper()
    has_accent = any(c in _ACCENTED for c in text_upper)
    base_y_offset = _ACCENT_SHIFT if has_accent else 0

    pixels: list = []
    cursor_x = 0
    for char in text_upper:
        if char not in _TEXT_CHARSET:
            continue
        width, on_pixels = _GLYPH_DATA[char]
        # Accented glyphs already span rows 0-7; never shift them.
        y_offset = 0 if char in _ACCENTED else base_y_offset
        for (row, col) in on_pixels:
            pixels.append(Pixel(x=cursor_x + col, y=row + y_offset, fill=''))
        cursor_x += width + _INTER_GLYPH_GAP
    return pixels


def pixel_text_width(text: str) -> int:
    """
    Total design-pixel width of the rendered string after skipping
    unsupported characters. Returns 0 for empty or all-unsupported input.
    """
    supported = [c for c in text.upper() if c in _TEXT_CHARSET]
    if not supported:
        return 0
    total = sum(_GLYPH_DATA[c][0] for c in supported)
    total += _INTER_GLYPH_GAP * (len(supported) - 1)
    return total


def pixel_text_height(text: str) -> int:
    """
    Design-pixel height of the rendered string. 8 when any accented uppercase
    letter (Á É Í Ó Ú Ñ) is present, otherwise 7. Used by the pixel_text macro
    to size the SVG viewBox so the diacritic row has dedicated headroom.
    """
    if any(c in _ACCENTED for c in text.upper()):
        return _ACCENT_HEIGHT
    return _BASE_HEIGHT
