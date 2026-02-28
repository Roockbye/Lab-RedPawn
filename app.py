#!/usr/bin/env python3
"""
Lab RedPawn — SOC Blue Team Interactive Lab
Application Flask principale — avec protections anti-triche
"""

import os
import markdown as md
import threading
from markupsafe import Markup
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from config import SECRET_KEY, LEVELS, CATEGORIES, SCOREBOARD_SERVER
from database import (
    init_db, create_player, get_player, submit_answer, use_hint,
    get_hints_used, get_player_progress, get_scoreboard, start_challenge,
    get_player_stats, upsert_remote_player, get_combined_scoreboard,
    get_local_player_data
)
from challenges.registry import ALL_CHALLENGES, get_challenge
from security import (
    init_answer_store, verify_answer, check_rate_limit, record_attempt,
    sanitize_challenge, add_security_headers
)

app = Flask(__name__)
app.secret_key = SECRET_KEY


# ============ Jinja2 Filters ============

@app.template_filter('markdown')
def markdown_filter(text):
    """Convertir du Markdown en HTML pour les briefings."""
    return Markup(md.markdown(text, extensions=['tables', 'fenced_code']))


# Initialize DB on startup
init_db()

# Initialize answer hash store (anti-triche)
nb_answers = init_answer_store(ALL_CHALLENGES)
print(f"    🔒 {nb_answers} réponses hachées et sécurisées")


# ============ Scoreboard réseau — sync helper ============

def _sync_score_to_server(player_id):
    """Push local player score to the central scoreboard server (background)."""
    if not SCOREBOARD_SERVER:
        return
    try:
        import urllib.request
        import json as _json
        data = get_local_player_data(player_id)
        if not data:
            return
        data["source_host"] = request.host
        payload = _json.dumps(data).encode("utf-8")
        url = SCOREBOARD_SERVER.rstrip("/") + "/api/scoreboard/report"
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass  # Silently fail — network may be down


# ============ Middleware de sécurité ============

@app.after_request
def apply_security_headers(response):
    """Appliquer les en-têtes de sécurité à toutes les réponses."""
    return add_security_headers(response)


# ============ Routes ============


@app.route("/")
def index():
    """Landing page — login or dashboard."""
    if "player_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/login", methods=["POST"])
def login():
    """Player login/registration."""
    username = request.form.get("username", "").strip()
    if not username or len(username) < 2 or len(username) > 30:
        flash("Nom d'utilisateur invalide (2-30 caractères).", "error")
        return redirect(url_for("index"))

    player = create_player(username)
    session["player_id"] = player["id"]
    session["username"] = player["username"]
    # Sync existing score to central server
    threading.Thread(target=_sync_score_to_server, args=(player["id"],), daemon=True).start()
    flash(f"Bienvenue, {username} ! Prêt pour la mission ?", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    """Player logout."""
    session.clear()
    return redirect(url_for("index"))


@app.route("/dashboard")
def dashboard():
    """Main dashboard with challenge overview."""
    if "player_id" not in session:
        return redirect(url_for("index"))

    player = get_player(session["player_id"])
    progress = get_player_progress(session["player_id"])
    stats = get_player_stats(session["player_id"])

    # Build progress map
    solved_map = {}
    for s in progress:
        key = s["challenge_id"]
        if key not in solved_map:
            solved_map[key] = set()
        solved_map[key].add(s["question_id"])

    # Organize challenges by level
    challenges_by_level = {}
    for c in ALL_CHALLENGES:
        level = c["level"]
        if level not in challenges_by_level:
            challenges_by_level[level] = []

        total_q = len(c["questions"])
        solved_q = len(solved_map.get(c["id"], set()))
        c_info = {
            **c,
            "solved": solved_q,
            "total": total_q,
            "progress_pct": int((solved_q / total_q) * 100) if total_q > 0 else 0,
            "is_complete": solved_q == total_q,
        }
        challenges_by_level[level].append(c_info)

    # Calculate total possible points
    total_possible = sum(c["points_total"] for c in ALL_CHALLENGES)

    # Check if all challenges are completed
    all_complete = all(
        len(solved_map.get(c["id"], set())) == len(c["questions"])
        for c in ALL_CHALLENGES
    )

    return render_template(
        "dashboard.html",
        player=player,
        challenges_by_level=challenges_by_level,
        levels=LEVELS,
        categories=CATEGORIES,
        stats=stats,
        total_possible=total_possible,
        solved_map=solved_map,
        all_complete=all_complete,
    )


@app.route("/challenge/<challenge_id>")
def challenge_view(challenge_id):
    """View a single challenge."""
    if "player_id" not in session:
        return redirect(url_for("index"))

    challenge = get_challenge(challenge_id)
    if not challenge:
        flash("Challenge introuvable.", "error")
        return redirect(url_for("dashboard"))

    player_id = session["player_id"]
    start_challenge(player_id, challenge_id)

    # Get solved questions for this challenge
    progress = get_player_progress(player_id)
    solved_questions = set()
    points_earned = 0
    for s in progress:
        if s["challenge_id"] == challenge_id:
            solved_questions.add(s["question_id"])
            points_earned += s["points_awarded"]

    # Get hints used for each question
    questions_with_hints = []
    for q in challenge["questions"]:
        hints_used_list = get_hints_used(player_id, challenge_id, q["id"])
        hints_list = q.get("hints", [])
        # Ne PAS envoyer les hints non révélés au client
        revealed_hints_text = [hints_list[i] for i in hints_used_list if i < len(hints_list)]
        q_info = {
            "id": q["id"],
            "text": q["text"],
            "points": q["points"],
            "hint_cost": q.get("hint_cost", 10),
            "is_solved": q["id"] in solved_questions,
            "hints_revealed": revealed_hints_text,
            "hints_available": len(hints_list),
            "hints_used_count": len(hints_used_list),
        }
        questions_with_hints.append(q_info)

    level_info = LEVELS.get(challenge["level"], {})
    category_info = CATEGORIES.get(challenge["category"], {})

    return render_template(
        "challenge.html",
        challenge=challenge,
        questions=questions_with_hints,
        solved_questions=solved_questions,
        points_earned=points_earned,
        level_info=level_info,
        category_info=category_info,
    )


@app.route("/submit", methods=["POST"])
def submit():
    """Submit an answer for a question — avec anti-triche."""
    if "player_id" not in session:
        return jsonify({"error": "Non authentifié"}), 401

    data = request.get_json()
    challenge_id = data.get("challenge_id")
    question_id = data.get("question_id")
    answer = data.get("answer", "").strip()

    if not all([challenge_id, question_id, answer]):
        return jsonify({"error": "Données manquantes"}), 400

    player_id = session["player_id"]

    challenge = get_challenge(challenge_id)
    if not challenge:
        return jsonify({"error": "Challenge introuvable"}), 404

    # Find the question (sans réponse, juste pour les points/metadata)
    question = None
    for q in challenge["questions"]:
        if q["id"] == question_id:
            question = q
            break

    if not question:
        return jsonify({"error": "Question introuvable"}), 404

    # ===== RATE LIMITING =====
    max_attempts = question.get("max_attempts")
    allowed, wait = check_rate_limit(player_id, challenge_id, question_id, max_attempts)
    if not allowed:
        return jsonify({
            "status": "rate_limited",
            "message": f"⏳ Trop de tentatives. Attendez {wait}s avant de réessayer.",
            "wait": wait,
        }), 429

    # ===== VÉRIFICATION PAR HASH (anti-triche) =====
    is_correct = verify_answer(challenge_id, question_id, answer)

    # Calculate points with hint penalty
    hints_used_list = get_hints_used(player_id, challenge_id, question_id)
    hint_penalty = len(hints_used_list) * question.get("hint_cost", 10)
    points = max(question["points"] - hint_penalty, question["points"] // 4)

    result = submit_answer(player_id, challenge_id, question_id, answer, is_correct, points, len(hints_used_list))

    if result["status"] == "already_solved":
        return jsonify({
            "status": "already_solved",
            "message": "✅ Déjà résolu !",
            "points": 0,
        })

    if is_correct:
        # Sync to central scoreboard in background
        threading.Thread(target=_sync_score_to_server, args=(player_id,), daemon=True).start()
        # JAMAIS envoyer la réponse ou le flag dans la réponse API
        return jsonify({
            "status": "correct",
            "message": f"🎯 Correct ! +{points} points",
            "points": points,
        })
    else:
        # Enregistrer la tentative échouée pour le rate limiting
        record_attempt(player_id, challenge_id, question_id)
        return jsonify({
            "status": "incorrect",
            "message": "❌ Mauvaise réponse. Réessayez !",
            "points": 0,
        })


@app.route("/hint", methods=["POST"])
def get_hint():
    """Get a hint for a question — accès contrôlé."""
    if "player_id" not in session:
        return jsonify({"error": "Non authentifié"}), 401

    data = request.get_json()
    challenge_id = data.get("challenge_id")
    question_id = data.get("question_id")

    if not all([challenge_id, question_id]):
        return jsonify({"error": "Données manquantes"}), 400

    challenge = get_challenge(challenge_id)
    if not challenge:
        return jsonify({"error": "Challenge introuvable"}), 404

    question = None
    for q in challenge["questions"]:
        if q["id"] == question_id:
            question = q
            break

    if not question:
        return jsonify({"error": "Question introuvable"}), 404

    player_id = session["player_id"]
    hints_used_list = get_hints_used(player_id, challenge_id, question_id)
    all_hints = question.get("hints", [])

    if len(hints_used_list) >= len(all_hints):
        return jsonify({"error": "Plus d'indices disponibles"}), 400

    next_hint_index = len(hints_used_list)
    use_hint(player_id, challenge_id, question_id, next_hint_index)

    hint_cost = question.get("hint_cost", 10)
    # Envoyer UNIQUEMENT l'indice demandé (pas tous les indices)
    return jsonify({
        "hint": all_hints[next_hint_index],
        "hint_number": next_hint_index + 1,
        "cost": hint_cost,
        "remaining": len(all_hints) - next_hint_index - 1,
    })


@app.route("/scoreboard")
def scoreboard_view():
    """Scoreboard page."""
    if "player_id" not in session:
        return redirect(url_for("index"))

    is_networked = bool(SCOREBOARD_SERVER)

    if is_networked:
        # Pull scoreboard from central server
        board = _pull_remote_scoreboard()
        if board is None:
            # Fallback to local + remote combined
            board = get_combined_scoreboard()
    else:
        board = get_combined_scoreboard()

    total_possible = sum(c["points_total"] for c in ALL_CHALLENGES)
    total_questions = sum(len(c["questions"]) for c in ALL_CHALLENGES)

    return render_template(
        "scoreboard.html",
        scoreboard=board,
        total_possible=total_possible,
        total_questions=total_questions,
        current_player_id=session["player_id"],
        current_username=session.get("username", ""),
        is_networked=is_networked,
    )


def _pull_remote_scoreboard():
    """Pull the combined scoreboard from the central server."""
    if not SCOREBOARD_SERVER:
        return None
    try:
        import urllib.request
        import json as _json
        url = SCOREBOARD_SERVER.rstrip("/") + "/api/scoreboard"
        req = urllib.request.Request(url)
        resp = urllib.request.urlopen(req, timeout=5)
        data = _json.loads(resp.read().decode("utf-8"))
        return data.get("scoreboard", [])
    except Exception:
        return None


@app.route("/api/scoreboard/report", methods=["POST"])
def api_scoreboard_report():
    """Receive score data from a remote instance."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Données manquantes"}), 400

    username = data.get("username", "").strip()
    source_host = data.get("source_host", request.remote_addr)
    total_score = data.get("total_score", 0)
    questions_solved = data.get("questions_solved", 0)

    if not username:
        return jsonify({"error": "Username requis"}), 400

    upsert_remote_player(username, source_host, total_score, questions_solved)
    return jsonify({"status": "ok"})


@app.route("/api/scoreboard")
def api_scoreboard():
    """Return the combined scoreboard as JSON (for remote instances to pull)."""
    board = get_combined_scoreboard()
    return jsonify({"scoreboard": board})


@app.route("/api/progress")
def api_progress():
    """API endpoint for real-time progress."""
    if "player_id" not in session:
        return jsonify({"error": "Non authentifié"}), 401

    player = get_player(session["player_id"])
    progress = get_player_progress(session["player_id"])
    stats = get_player_stats(session["player_id"])

    return jsonify({
        "player": player,
        "progress": progress,
        "stats": stats,
    })


if __name__ == "__main__":
    print(r"""
    ╔══════════════════════════════════════════════════════╗
    ║                                                      ║
    ║   ██████╗ ███████╗██████╗ ██████╗  █████╗ ██╗    ██╗║
    ║   ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██║    ██║║
    ║   ██████╔╝█████╗  ██║  ██║██████╔╝███████║██║ █╗ ██║║
    ║   ██╔══██╗██╔══╝  ██║  ██║██╔═══╝ ██╔══██║██║███╗██║║
    ║   ██║  ██║███████╗██████╔╝██║     ██║  ██║╚███╔███╔╝║
    ║   ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚══╝╚══╝║
    ║                                                      ║
    ║        🛡️  SOC Blue Team — Interactive Lab  🛡️        ║
    ║                                                      ║
    ╚══════════════════════════════════════════════════════╝
    """)
    print("    🚀 Lab démarré sur http://127.0.0.1:5050")
    print(f"    📋 {len(ALL_CHALLENGES)} challenges | 5 niveaux | {sum(len(c['questions']) for c in ALL_CHALLENGES)} questions")
    print("    🔒 Anti-triche activé (hachage + rate limiting)")
    if SCOREBOARD_SERVER:
        print(f"    🌐 Scoreboard réseau → {SCOREBOARD_SERVER}")
    else:
        print("    📡 Scoreboard local (SCOREBOARD_SERVER non configuré)")
    print("    🏆 Que la chasse commence !\n")
    app.run(debug=True, host="0.0.0.0", port=5050)
