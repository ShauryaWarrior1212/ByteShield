let player = document.getElementById('player');
let gameArea = document.getElementById('gameArea');
let scoreDisplay = document.getElementById('score');
let startBtn = document.getElementById('startBtn');
let controls = document.getElementById('controls');
let leftBtn = document.getElementById('leftBtn');
let rightBtn = document.getElementById('rightBtn');
let score = 0;
let gameInterval;
let threatInterval;

function startGame() {
    score = 0;
    scoreDisplay.innerHTML = "Score: " + score;
    startBtn.style.display = "none";
    controls.style.display = "flex"; // Show control buttons
    player.style.left = '50%'; // Reset player position

    gameInterval = setInterval(movePlayer, 20);
    threatInterval = setInterval(spawnThreat, 1000);
}

function movePlayer(e) {
    let playerLeft = player.offsetLeft;

    if (e.type === 'keydown') {
        if (e.key === 'ArrowLeft' && playerLeft > 0) {
            player.style.left = playerLeft - 20 + 'px';
        } else if (e.key === 'ArrowRight' && playerLeft < (gameArea.offsetWidth - player.offsetWidth)) {
            player.style.left = playerLeft + 20 + 'px';
        }
    } else if (e.type === 'click') {
        if (this.id === 'leftBtn' && playerLeft > 0) {
            player.style.left = playerLeft - 20 + 'px';
        } else if (this.id === 'rightBtn' && playerLeft < (gameArea.offsetWidth - player.offsetWidth)) {
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
    let threats = document.getElementsByClassName('threat');
    while (threats[0]) {
        threats[0].parentNode.removeChild(threats[0]);
    }
    alert("Game Over! Your Score: " + score);
    startBtn.style.display = "block";
    controls.style.display = "none"; // Hide control buttons
}

startBtn.addEventListener('click', startGame);
document.addEventListener('keydown', movePlayer);
leftBtn.addEventListener('click', movePlayer);
rightBtn.addEventListener('click', movePlayer);
