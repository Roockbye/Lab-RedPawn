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
            setTimeout(() => location.reload(), 1200);
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

// Shake animation CSS is added dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes shake {
        0%, 100% { transform: translateX(0); }
        10%, 30%, 50%, 70%, 90% { transform: translateX(-4px); }
        20%, 40%, 60%, 80% { transform: translateX(4px); }
    }
    .shake { animation: shake 0.5s ease; }
`;
document.head.appendChild(style);
