let player = document.getElementById('player');
let gameArea = document.getElementById('gameArea');
let scoreDisplay = document.getElementById('score');
let startBtn = document.getElementById('startBtn');
let score = 0;
let gameInterval;
let threatInterval;

function startGame() {
    score = 0;
    scoreDisplay.innerHTML = "Score: " + score;
    startBtn.style.display = "none";

    gameInterval = setInterval(movePlayer, 20);
    threatInterval = setInterval(spawnThreat, 1000);
}

function movePlayer(e) {
    document.onkeydown = function(e) {
        let playerLeft = player.offsetLeft;
        if (e.key === 'ArrowLeft' && playerLeft > 0) {
            player.style.left = playerLeft - 20 + 'px';
        } else if (e.key === 'ArrowRight' && playerLeft < (gameArea.offsetWidth - player.offsetWidth)) {
            player.style.left = playerLeft + 20 + 'px';
        }
    }
}

function spawnThreat() {
    let threat = document.createElement('div');
    threat.className = 'threat';
    threat.style.left = Math.random() * (gameArea.offsetWidth - 30) + 'px';
    gameArea.appendChild(threat);

    let moveThreat = setInterval(function() {
        let threatTop = threat.offsetTop;
        if (threatTop < gameArea.offsetHeight) {
            threat.style.top = threatTop + 5 + 'px';
        } else {
            gameArea.removeChild(threat);
            clearInterval(moveThreat);
            score++;
            scoreDisplay.innerHTML = "Score: " + score;
        }

        if (checkCollision(player, threat)) {
            gameOver();
            clearInterval(moveThreat);
        }
    }, 20);
}

function checkCollision(player, threat) {
    let playerRect = player.getBoundingClientRect();
    let threatRect = threat.getBoundingClientRect();

    return !(playerRect.top > threatRect.bottom ||
             playerRect.bottom < threatRect.top ||
             playerRect.left > threatRect.right ||
             playerRect.right < threatRect.left);
}

function gameOver() {
    clearInterval(gameInterval);
    clearInterval(threatInterval);
    startBtn.style.display = "block";
    alert("Game Over! Your Score: " + score);
}

startBtn.addEventListener('click', startGame);
