"""
RedPawn SOC Lab — Module de sécurité et anti-triche.

Protections :
- Hachage SHA-256 des réponses (jamais de plaintext côté client)
- Rate limiting par joueur/question (anti brute-force)
- Cooldown entre les tentatives
- Sanitisation des données challenge avant envoi au client
- En-têtes de sécurité HTTP
"""

import hashlib
import time
import re
import copy
from collections import defaultdict


# ============ Configuration Anti-Triche ============

# Sel cryptographique pour le hachage des réponses
# Même en lisant le code source, il faut reverse le hash+sel pour trouver la réponse
ANSWER_SALT = "R3dP@wN_50C_L4B_2026_x7f9a2_HMAC_PR1V4T3_K3Y"

# Rate limiting
RATE_LIMIT_WINDOW = 30          # Fenêtre en secondes
RATE_LIMIT_MAX_ATTEMPTS = 5     # Max tentatives erronées dans la fenêtre
COOLDOWN_BETWEEN_ATTEMPTS = 3   # Secondes minimum entre 2 soumissions

# Regex pour extraire le contenu d'un FLAG{...} ou REDPAWN{...}
FLAG_PATTERN = re.compile(r'^(?:FLAG|REDPAWN)\{(.+)\}$', re.IGNORECASE)


# ============ Stockage en mémoire ============

# Tracker des tentatives : clé = (player_id, challenge_id, question_id) → [timestamps]
_attempts = defaultdict(list)

# Store des hashes de réponses : clé = (challenge_id, question_id) → set de hashes acceptables
_answer_store = {}


# ============ Fonctions de hachage ============

def hash_answer(text):
    """Hacher une réponse avec sel pour comparaison sécurisée."""
    normalized = text.lower().strip()
    return hashlib.sha256(f"{ANSWER_SALT}:{normalized}".encode()).hexdigest()


def init_answer_store(challenges):
    """
    Construire le store de hashes à partir des définitions de challenges.
    Appelé une seule fois au démarrage de l'application.
    Les réponses en clair restent dans les fichiers Python (pour l'admin)
    mais ne sont JAMAIS envoyées au client.
    """
    global _answer_store
    _answer_store.clear()

    for challenge in challenges:
        cid = challenge["id"]
        for question in challenge["questions"]:
            qid = question["id"]
            key = (cid, qid)
            hashes = set()

            # Hacher la réponse brute
            if "answer" in question:
                raw = question["answer"]
                hashes.add(hash_answer(raw))

            # Hacher le contenu du FLAG et le FLAG complet
            if "flag" in question:
                flag_str = question["flag"]
                hashes.add(hash_answer(flag_str))
                match = FLAG_PATTERN.match(flag_str)
                if match:
                    inner = match.group(1)
                    hashes.add(hash_answer(inner))
                    # Accepter aussi espaces au lieu d'underscores
                    if "_" in inner:
                        hashes.add(hash_answer(inner.replace("_", " ")))

            _answer_store[key] = hashes

    return len(_answer_store)


# ============ Vérification des réponses ============

def verify_answer(challenge_id, question_id, user_input):
    """
    Vérifier la réponse d'un utilisateur contre les hashes stockés.
    Accepte : réponse brute, REDPAWN{réponse}, FLAG{réponse}, avec underscores ou espaces
    """
    key = (challenge_id, question_id)
    if key not in _answer_store:
        return False

    acceptable = _answer_store[key]
    user_clean = user_input.strip()

    # Essayer l'input brut
    if hash_answer(user_clean) in acceptable:
        return True

    # Essayer en extrayant le contenu de FLAG{...}
    match = FLAG_PATTERN.match(user_clean)
    if match:
        inner = match.group(1)
        if hash_answer(inner) in acceptable:
            return True
        # Essayer avec espaces au lieu d'underscores
        if hash_answer(inner.replace("_", " ")) in acceptable:
            return True

    return False


# ============ Rate Limiting ============

def check_rate_limit(player_id, challenge_id, question_id, max_attempts=None):
    """
    Vérifier si un joueur est limité en fréquence.
    Retourne (autorisé: bool, temps_attente: float)
    max_attempts: override du nombre max de tentatives (par défaut RATE_LIMIT_MAX_ATTEMPTS)
    """
    key = (player_id, challenge_id, question_id)
    now = time.time()
    limit = max_attempts if max_attempts is not None else RATE_LIMIT_MAX_ATTEMPTS

    # Nettoyer les entrées hors fenêtre
    _attempts[key] = [t for t in _attempts[key] if now - t < RATE_LIMIT_WINDOW]
    entries = _attempts[key]

    # Vérifier le cooldown entre tentatives
    if entries:
        since_last = now - entries[-1]
        if since_last < COOLDOWN_BETWEEN_ATTEMPTS:
            return False, round(COOLDOWN_BETWEEN_ATTEMPTS - since_last, 1)

    # Vérifier le nombre max de tentatives
    if len(entries) >= limit:
        oldest = entries[0]
        wait = RATE_LIMIT_WINDOW - (now - oldest)
        return False, round(wait, 1)

    return True, 0


def record_attempt(player_id, challenge_id, question_id):
    """Enregistrer une tentative échouée pour le rate limiting."""
    key = (player_id, challenge_id, question_id)
    _attempts[key].append(time.time())


# ============ Sanitisation ============

def sanitize_challenge(challenge):
    """
    Supprimer TOUS les champs sensibles d'un challenge avant envoi au client.
    Appelé avant chaque render_template ou jsonify.
    """
    clean = copy.deepcopy(challenge)
    for q in clean.get("questions", []):
        # Supprimer les réponses
        q.pop("answer", None)
        q.pop("flag", None)
        q.pop("_answer_hashes", None)
        # Garder hints (ils sont gérés côté serveur via l'API /hint)
        # mais ne pas les envoyer dans le template — géré par l'app
        q.pop("hints", None)
    return clean


def sanitize_question(question):
    """Supprimer les champs sensibles d'une question individuelle."""
    clean = dict(question)
    clean.pop("answer", None)
    clean.pop("flag", None)
    clean.pop("_answer_hashes", None)
    clean.pop("hints", None)
    return clean


# ============ En-têtes de sécurité HTTP ============

def add_security_headers(response):
    """Ajouter des en-têtes de sécurité à chaque réponse HTTP."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # Empêcher la mise en cache des réponses API
    response.headers['Surrogate-Control'] = 'no-store'
    return response
