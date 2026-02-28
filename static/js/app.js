/**
 * RedPawn SOC Lab — Client-side JavaScript
 */

// ============ Answer Submission ============
async function submitAnswer(challengeId, questionId) {
    const input = document.getElementById(`answer-${questionId}`);
    const feedback = document.getElementById(`feedback-${questionId}`);
    const answer = input.value.trim();

    if (!answer) {
        showFeedback(feedback, "⚠️ Entrez une réponse.", "incorrect");
        input.focus();
        return;
    }

    // Disable during submission
    input.disabled = true;
    const btn = input.parentElement.querySelector('.submit-btn');
    btn.disabled = true;
    btn.textContent = '⏳';

    try {
        const response = await fetch('/submit', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                challenge_id: challengeId,
                question_id: questionId,
                answer: answer,
            }),
        });

        const data = await response.json();

        if (data.status === 'correct') {
            showFeedback(feedback, data.message, 'correct');
            const card = document.getElementById(`question-${questionId}`);
            card.classList.add('solved');
            
            // Check if all questions are now solved
            const totalQuestions = document.querySelectorAll('.question-card').length;
            const solvedQuestions = document.querySelectorAll('.question-card.solved').length;
            
            if (solvedQuestions >= totalQuestions) {
                // All questions answered — celebration!
                showChallengeComplete();
                setTimeout(() => location.reload(), 4000);
            } else {
                setTimeout(() => location.reload(), 1200);
            }
        } else if (data.status === 'already_solved') {
            showFeedback(feedback, data.message, 'already');
        } else if (data.status === 'rate_limited') {
            showFeedback(feedback, data.message, 'rate-limited');
            input.disabled = true;
            btn.disabled = true;
            btn.textContent = '⏳';
            // Réactiver après le cooldown
            const wait = (data.wait || 3) * 1000;
            setTimeout(() => {
                input.disabled = false;
                btn.disabled = false;
                btn.textContent = 'Valider';
                feedback.textContent = '';
                input.focus();
            }, wait);
        } else {
            showFeedback(feedback, data.message, 'incorrect');
            input.disabled = false;
            btn.disabled = false;
            btn.textContent = 'Valider';
            // Shake animation
            input.classList.add('shake');
            setTimeout(() => input.classList.remove('shake'), 500);
            input.select();
        }
    } catch (error) {
        showFeedback(feedback, "❌ Erreur réseau. Réessayez.", "incorrect");
        input.disabled = false;
        btn.disabled = false;
        btn.textContent = 'Valider';
    }
}

// ============ Hint Request ============
async function requestHint(challengeId, questionId) {
    const hintBtn = event.target;

    if (!confirm("Utiliser un indice ? Cela réduira les points gagnables pour cette question.")) {
        return;
    }

    hintBtn.disabled = true;

    try {
        const response = await fetch('/hint', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                challenge_id: challengeId,
                question_id: questionId,
            }),
        });

        const data = await response.json();

        if (data.error) {
            alert(data.error);
            hintBtn.disabled = false;
            return;
        }

        // Add hint to list
        const hintsList = document.getElementById(`hints-${questionId}`);
        const hintCard = document.createElement('div');
        hintCard.className = 'hint-card revealed';
        hintCard.innerHTML = `
            <span class="hint-icon">💡</span>
            <span class="hint-text">${escapeHtml(data.hint)}</span>
        `;
        hintsList.appendChild(hintCard);

        // Update button text
        if (data.remaining > 0) {
            hintBtn.disabled = false;
            hintBtn.textContent = `💡 Indice (${data.hint_number}/${data.hint_number + data.remaining}) — coût: -${data.cost} pts`;
        } else {
            hintBtn.textContent = '💡 Tous les indices utilisés';
        }
    } catch (error) {
        alert("Erreur réseau lors de la récupération de l'indice.");
        hintBtn.disabled = false;
    }
}

// ============ Feedback Display ============
function showFeedback(element, message, type) {
    element.textContent = message;
    element.className = `answer-feedback ${type}`;
}

// ============ Copy Artifact ============
document.addEventListener('DOMContentLoaded', () => {
    // Download artifact buttons
    document.querySelectorAll('.download-artifact').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const filename = btn.dataset.filename;
            const pre = btn.closest('.artifact-card').querySelector('pre code');
            if (pre) {
                const blob = new Blob([pre.textContent], { type: 'text/plain;charset=utf-8' });
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = filename;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                const original = btn.textContent;
                btn.textContent = '✅ Téléchargé !';
                setTimeout(() => btn.textContent = original, 2000);
            }
        });
    });

    // Copy artifact buttons
    document.querySelectorAll('.copy-artifact').forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const artifactIndex = btn.dataset.artifact;
            const pre = btn.closest('.artifact-card').querySelector('pre code');
            if (pre) {
                navigator.clipboard.writeText(pre.textContent).then(() => {
                    const original = btn.textContent;
                    btn.textContent = '✅ Copié !';
                    setTimeout(() => btn.textContent = original, 2000);
                }).catch(() => {
                    // Fallback
                    const textarea = document.createElement('textarea');
                    textarea.value = pre.textContent;
                    document.body.appendChild(textarea);
                    textarea.select();
                    document.execCommand('copy');
                    document.body.removeChild(textarea);
                    const original = btn.textContent;
                    btn.textContent = '✅ Copié !';
                    setTimeout(() => btn.textContent = original, 2000);
                });
            }
        });
    });

    // Enter key to submit
    document.querySelectorAll('.answer-input').forEach(input => {
        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const challengeId = input.dataset.challenge;
                const questionId = input.dataset.question;
                submitAnswer(challengeId, questionId);
            }
        });
    });

    // Auto-dismiss flash messages
    document.querySelectorAll('.flash').forEach(flash => {
        setTimeout(() => {
            flash.style.opacity = '0';
            flash.style.transform = 'translateX(100%)';
            setTimeout(() => flash.remove(), 300);
        }, 5000);
    });
});

// ============ Utility ============
function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// ============ Challenge Complete Animation ============
function showChallengeComplete() {
    // Create overlay
    const overlay = document.createElement('div');
    overlay.className = 'challenge-complete-overlay';
    overlay.innerHTML = `
        <div class="challenge-complete-content">
            <div class="complete-icon">🏆</div>
            <h2>Challenge Terminé !</h2>
            <p>Toutes les questions ont été résolues avec succès.</p>
        </div>
    `;
    document.body.appendChild(overlay);

    // Create confetti particles
    const colors = ['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4'];
    for (let i = 0; i < 80; i++) {
        const confetti = document.createElement('div');
        confetti.className = 'confetti-particle';
        confetti.style.left = Math.random() * 100 + 'vw';
        confetti.style.backgroundColor = colors[Math.floor(Math.random() * colors.length)];
        confetti.style.animationDelay = Math.random() * 2 + 's';
        confetti.style.animationDuration = (2 + Math.random() * 3) + 's';
        confetti.style.width = (6 + Math.random() * 8) + 'px';
        confetti.style.height = (6 + Math.random() * 8) + 'px';
        overlay.appendChild(confetti);
    }

    // Remove after animation
    setTimeout(() => {
        overlay.style.opacity = '0';
        setTimeout(() => overlay.remove(), 500);
    }, 3500);
}

// Shake animation CSS is added dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        10%, 30%, 50%, 70%, 90% { transform: translateX(-4px); }
        20%, 40%, 60%, 80% { transform: translateX(4px); }
    }
    .shake { animation: shake 0.5s ease; }

    @keyframes confettiFall {
        0% { transform: translateY(-10vh) rotate(0deg); opacity: 1; }
        100% { transform: translateY(110vh) rotate(720deg); opacity: 0; }
    }

    .challenge-complete-overlay {
        position: fixed;
        top: 0; left: 0;
        width: 100vw; height: 100vh;
        background: rgba(10, 14, 23, 0.85);
        z-index: 10000;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: opacity 0.5s ease;
        overflow: hidden;
    }

    .challenge-complete-content {
        text-align: center;
        z-index: 10001;
        animation: popIn 0.5s cubic-bezier(0.175, 0.885, 0.32, 1.275);
    }

    @keyframes popIn {
        0% { transform: scale(0.3); opacity: 0; }
        100% { transform: scale(1); opacity: 1; }
    }

    .complete-icon {
        font-size: 5rem;
        margin-bottom: 1rem;
        animation: bounce 0.6s ease infinite alternate;
    }

    @keyframes bounce {
        from { transform: translateY(0); }
        to { transform: translateY(-15px); }
    }

    .challenge-complete-content h2 {
        font-size: 2rem;
        color: #10b981;
        margin-bottom: 0.5rem;
        text-shadow: 0 0 20px rgba(16, 185, 129, 0.4);
    }

    .challenge-complete-content p {
        color: #9ca3af;
        font-size: 1.1rem;
    }

    .confetti-particle {
        position: absolute;
        top: -10px;
        border-radius: 2px;
        animation: confettiFall linear forwards;
    }
`;
document.head.appendChild(style);
// ───── Badge completion: dismiss + fireworks ─────
function dismissBadge() {
    const overlay = document.getElementById('badge-overlay');
    if (!overlay) return;
    overlay.classList.add('dismissed');
    sessionStorage.setItem('badge_dismissed', '1');
    setTimeout(() => overlay.remove(), 600);
}

(function initBadgeFireworks() {
    const container = document.getElementById('badge-fireworks');
    if (!container) return;
    if (sessionStorage.getItem('badge_dismissed') === '1') {
        const overlay = document.getElementById('badge-overlay');
        if (overlay) overlay.remove();
        return;
    }
    const colors = ['#d4af37', '#f5d442', '#ff6b6b', '#10b981', '#6366f1', '#f472b6', '#ffffff'];
    function burst(cx, cy) {
        for (let i = 0; i < 30; i++) {
            const p = document.createElement('span');
            p.className = 'firework-particle';
            const angle = Math.random() * Math.PI * 2;
            const dist = 80 + Math.random() * 200;
            p.style.left = cx + 'px';
            p.style.top = cy + 'px';
            p.style.setProperty('--fx', Math.cos(angle) * dist + 'px');
            p.style.setProperty('--fy', Math.sin(angle) * dist + 'px');
            p.style.background = colors[Math.floor(Math.random() * colors.length)];
            p.style.animationDuration = (1 + Math.random()) + 's';
            p.style.animationDelay = (Math.random() * 0.3) + 's';
            container.appendChild(p);
            setTimeout(() => p.remove(), 2500);
        }
    }
    // Initial bursts
    setTimeout(() => burst(container.offsetWidth * 0.3, container.offsetHeight * 0.3), 400);
    setTimeout(() => burst(container.offsetWidth * 0.7, container.offsetHeight * 0.4), 800);
    setTimeout(() => burst(container.offsetWidth * 0.5, container.offsetHeight * 0.2), 1200);
    setTimeout(() => burst(container.offsetWidth * 0.2, container.offsetHeight * 0.6), 1600);
    setTimeout(() => burst(container.offsetWidth * 0.8, container.offsetHeight * 0.5), 2000);
})();