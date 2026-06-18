# WikiSTEM | Javier Fernando Vega Alamo | CS50x 2026
# This file was drafted with assistance from Claude (Anthropic) inside
# Google Antigravity, working from a specification I authored. All
# architectural decisions, security choices, and final logic were
# reviewed and verified by me before commit.

from datetime import datetime, timedelta, timezone   # v4: timezone was missing in v3
from collections import Counter

from sqlalchemy.orm import joinedload

from models import Submission, ViewHistory, SubmissionLike

# PERF (audit finding P2): personalisation scoring runs in Python, so the candidate
# pool pulled from SQL must be bounded — otherwise a growing corpus means an
# unbounded SELECT + scan on every homepage load. Cap to the most recent N approved
# items per query; older items are already unlikely to surface above newer ones.
CANDIDATE_CAP = 200

# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _score_candidate(s, top_cats, preferred_track, liked_tags, now):
    """Score a single submission against a user's engagement signals."""
    score = 0
    if top_cats and s.category == top_cats[0]:
        score += 3
    if len(top_cats) > 1 and s.category == top_cats[1]:
        score += 2
    if s.track == preferred_track:
        score += 1
    if s.tags and liked_tags:
        stags  = {t.strip().lower() for t in s.tags.split(',')}
        score += len(stags & liked_tags)
    if s.views > 200:
        score += 2
    elif s.views > 50:
        score += 1
    if (now - s.created_at) < timedelta(days=30):
        score += 1
    return score


def _personalization_signals(user_id):
    """
    Derive personalisation signals from a user's view and like history.

    Returns (viewed_ids, top_cats, preferred_track, liked_tags).
    Returns (None, [], None, set()) when the user has no engagement history
    so callers can branch cleanly on `if viewed is None`.
    """
    viewed_ids = {v.submission_id for v in
                  ViewHistory.query.filter_by(user_id=user_id).all()}
    liked_ids  = {l.submission_id for l in
                  SubmissionLike.query.filter_by(user_id=user_id).all()}
    engaged    = viewed_ids | liked_ids

    if not engaged:
        return None, [], None, set()

    engaged_subs    = Submission.query.filter(Submission.id.in_(engaged)).all()
    category_counts = Counter(s.category for s in engaged_subs)
    top_cats        = [c for c, _ in category_counts.most_common(2)]
    track_counts    = Counter(s.track for s in engaged_subs)
    preferred_track = track_counts.most_common(1)[0][0]

    liked_tags = set()
    for s in (x for x in engaged_subs if x.id in liked_ids):
        if s.tags:
            liked_tags.update(t.strip().lower() for t in s.tags.split(','))

    return viewed_ids, top_cats, preferred_track, liked_tags

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def recommend_submissions(user_id, limit=6):
    """
    Return up to `limit` recommended submissions for an authenticated user.
    Single mixed-track list — kept for backwards-compatible use cases.
    For the homepage two-column feed use recommend_split_for_user().
    """
    viewed, top_cats, preferred_track, liked_tags = _personalization_signals(user_id)

    if viewed is None:
        return (Submission.query.options(joinedload(Submission.author))
                .filter_by(status='approved')
                .filter(Submission.author_id != user_id)
                .order_by(Submission.created_at.desc())
                .limit(limit).all())

    # Bounded candidate pool (P2): newest CANDIDATE_CAP unseen approved items.
    candidates = (Submission.query.options(joinedload(Submission.author))
                  .filter_by(status='approved')
                  .filter(Submission.author_id != user_id)
                  .filter(~Submission.id.in_(viewed))
                  .order_by(Submission.created_at.desc())
                  .limit(CANDIDATE_CAP).all())

    # created_at is read back from SQLite as a NAIVE datetime (the db.DateTime
    # column has no tzinfo), so compare against a naive UTC 'now' — subtracting
    # an aware from a naive datetime raises TypeError.
    now    = datetime.now(timezone.utc).replace(tzinfo=None)
    scored = [(_score_candidate(s, top_cats, preferred_track, liked_tags, now), s)
              for s in candidates]
    scored.sort(key=lambda x: x[0], reverse=True)
    return [s for _, s in scored[:limit]]


def recommend_split_for_user(user_id, per_column=5):
    """
    Return (recent_research, recent_projects) — the two parallel lists the
    homepage two-column feed (frontend §7.2) expects.

    For new users (no engagement signals) returns the most recent approved
    submissions per track. For engaged users applies personalisation scoring
    filtered by track, then tops up with newest unseen items if the scored
    pool is smaller than per_column.
    """
    viewed, top_cats, preferred_track, liked_tags = _personalization_signals(user_id)
    # Naive UTC to match SQLite's naive created_at (see recommend_submissions).
    now = datetime.now(timezone.utc).replace(tzinfo=None)

    def _track_list(track):
        if viewed is None:
            return (Submission.query.options(joinedload(Submission.author))
                    .filter_by(status='approved', track=track)
                    .filter(Submission.author_id != user_id)
                    .order_by(Submission.created_at.desc())
                    .limit(per_column).all())

        # Bounded candidate pool (P2): newest CANDIDATE_CAP unseen approved items
        # on this track, scored in Python below.
        candidates = (Submission.query.options(joinedload(Submission.author))
                      .filter_by(status='approved', track=track)
                      .filter(Submission.author_id != user_id)
                      .filter(~Submission.id.in_(viewed))
                      .order_by(Submission.created_at.desc())
                      .limit(CANDIDATE_CAP).all())

        scored = [(_score_candidate(s, top_cats, preferred_track, liked_tags, now), s)
                  for s in candidates]
        scored.sort(key=lambda x: x[0], reverse=True)
        chosen = [s for _, s in scored[:per_column]]

        # Top-up: if personalisation left fewer than per_column results, fill
        # with the newest approved submissions on this track not yet chosen.
        if len(chosen) < per_column:
            already  = {s.id for s in chosen}
            fillers  = (Submission.query.options(joinedload(Submission.author))
                        .filter_by(status='approved', track=track)
                        .filter(Submission.author_id != user_id)
                        .filter(~Submission.id.in_(already))
                        .order_by(Submission.created_at.desc())
                        .limit(per_column - len(chosen)).all())
            chosen.extend(fillers)

        return chosen

    return _track_list('research'), _track_list('project')


def recommend_split_for_guest(per_column=5):
    """
    Return (recent_research, recent_projects) with no personalisation.
    Used for unauthenticated visitors — most recent approved per track.
    """
    research = (Submission.query.options(joinedload(Submission.author))
                .filter_by(status='approved', track='research')
                .order_by(Submission.created_at.desc())
                .limit(per_column).all())
    projects = (Submission.query.options(joinedload(Submission.author))
                .filter_by(status='approved', track='project')
                .order_by(Submission.created_at.desc())
                .limit(per_column).all())
    return research, projects
