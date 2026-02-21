import sqlite3
import os
import json
from datetime import datetime
from config import DATABASE


def get_db():
    """Get database connection."""
    os.makedirs(os.path.dirname(DATABASE), exist_ok=True)
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Initialize the database schema."""
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS players (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_score INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS submissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            player_id INTEGER NOT NULL,
            challenge_id TEXT NOT NULL,
            question_id TEXT NOT NULL,
            answer TEXT NOT NULL,
            is_correct BOOLEAN NOT NULL,
            points_awarded INTEGER DEFAULT 0,
            hints_used INTEGER DEFAULT 0,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (player_id) REFERENCES players(id)
        );

        CREATE TABLE IF NOT EXISTS hints_used (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            player_id INTEGER NOT NULL,
            challenge_id TEXT NOT NULL,
            question_id TEXT NOT NULL,
            hint_index INTEGER NOT NULL,
            used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (player_id) REFERENCES players(id),
            UNIQUE(player_id, challenge_id, question_id, hint_index)
        );

        CREATE TABLE IF NOT EXISTS challenge_starts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            player_id INTEGER NOT NULL,
            challenge_id TEXT NOT NULL,
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (player_id) REFERENCES players(id),
            UNIQUE(player_id, challenge_id)
        );
    """)
    conn.commit()
    conn.close()


def create_player(username):
    """Create a new player."""
    conn = get_db()
    try:
        conn.execute("INSERT INTO players (username) VALUES (?)", (username,))
        conn.commit()
        player = conn.execute(
            "SELECT * FROM players WHERE username = ?", (username,)
        ).fetchone()
        return dict(player)
    except sqlite3.IntegrityError:
        player = conn.execute(
            "SELECT * FROM players WHERE username = ?", (username,)
        ).fetchone()
        return dict(player)
    finally:
        conn.close()


def get_player(player_id):
    """Get player by ID."""
    conn = get_db()
    player = conn.execute(
        "SELECT * FROM players WHERE id = ?", (player_id,)
    ).fetchone()
    conn.close()
    return dict(player) if player else None


def submit_answer(player_id, challenge_id, question_id, answer, is_correct, points, hints_used):
    """Record an answer submission."""
    conn = get_db()
    # Check if already correctly answered
    existing = conn.execute(
        """SELECT id FROM submissions 
           WHERE player_id = ? AND challenge_id = ? AND question_id = ? AND is_correct = 1""",
        (player_id, challenge_id, question_id)
    ).fetchone()

    if existing:
        conn.close()
        return {"status": "already_solved", "points": 0}

    conn.execute(
        """INSERT INTO submissions (player_id, challenge_id, question_id, answer, is_correct, points_awarded, hints_used)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (player_id, challenge_id, question_id, answer, is_correct, points if is_correct else 0, hints_used)
    )

    if is_correct:
        conn.execute(
            "UPDATE players SET total_score = total_score + ? WHERE id = ?",
            (points, player_id)
        )

    conn.commit()
    conn.close()
    return {"status": "correct" if is_correct else "incorrect", "points": points if is_correct else 0}


def use_hint(player_id, challenge_id, question_id, hint_index):
    """Record hint usage."""
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO hints_used (player_id, challenge_id, question_id, hint_index)
               VALUES (?, ?, ?, ?)""",
            (player_id, challenge_id, question_id, hint_index)
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def get_hints_used(player_id, challenge_id, question_id):
    """Get hints already used for a question."""
    conn = get_db()
    hints = conn.execute(
        """SELECT hint_index FROM hints_used
           WHERE player_id = ? AND challenge_id = ? AND question_id = ?
           ORDER BY hint_index""",
        (player_id, challenge_id, question_id)
    ).fetchall()
    conn.close()
    return [h["hint_index"] for h in hints]


def get_player_progress(player_id):
    """Get all solved questions for a player."""
    conn = get_db()
    solved = conn.execute(
        """SELECT challenge_id, question_id, points_awarded, submitted_at
           FROM submissions WHERE player_id = ? AND is_correct = 1
           ORDER BY submitted_at""",
        (player_id,)
    ).fetchall()
    conn.close()
    return [dict(s) for s in solved]


def get_scoreboard():
    """Get the full scoreboard."""
    conn = get_db()
    players = conn.execute(
        """SELECT p.id, p.username, p.total_score, p.created_at,
                  COUNT(DISTINCT s.challenge_id || ':' || s.question_id) as questions_solved
           FROM players p
           LEFT JOIN submissions s ON p.id = s.player_id AND s.is_correct = 1
           GROUP BY p.id
           ORDER BY p.total_score DESC, p.created_at ASC"""
    ).fetchall()
    conn.close()
    return [dict(p) for p in players]


def start_challenge(player_id, challenge_id):
    """Record challenge start time."""
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO challenge_starts (player_id, challenge_id) VALUES (?, ?)",
            (player_id, challenge_id)
        )
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()


def get_player_stats(player_id):
    """Get detailed stats for a player."""
    conn = get_db()
    stats = {
        "total_submissions": 0,
        "correct_submissions": 0,
        "total_hints": 0,
        "categories_completed": {},
        "time_spent": None,
    }

    total = conn.execute(
        "SELECT COUNT(*) as cnt FROM submissions WHERE player_id = ?", (player_id,)
    ).fetchone()
    stats["total_submissions"] = total["cnt"]

    correct = conn.execute(
        "SELECT COUNT(*) as cnt FROM submissions WHERE player_id = ? AND is_correct = 1",
        (player_id,)
    ).fetchone()
    stats["correct_submissions"] = correct["cnt"]

    hints = conn.execute(
        "SELECT COUNT(*) as cnt FROM hints_used WHERE player_id = ?", (player_id,)
    ).fetchone()
    stats["total_hints"] = hints["cnt"]

    conn.close()
    return stats
