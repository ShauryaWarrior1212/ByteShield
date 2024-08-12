document.addEventListener('DOMContentLoaded', function () {
    initializeMap();
    initializeChart();
    updateDashboard();
    setInterval(updateDashboard, 5000); // Update every 5 seconds
});

let map;
let markers = [];
let attackChart;
const attackSound = document.getElementById('attack-sound');

function initializeMap() {
    map = L.map('map').setView([20, 0], 2); // World view

    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 18,
    }).addTo(map);
}

function initializeChart() {
    const ctx = document.getElementById('attackChart').getContext('2d');

    attackChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Number of Attacks',
                data: [],
                borderColor: '#ff3333',
                backgroundColor: 'rgba(255, 51, 51, 0.2)',
                borderWidth: 2
            }]
        },
        options: {
            scales: {
                x: {
                    beginAtZero: true
                },
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function updateDashboard() {
    console.log('Fetching data...');

    fetch('/get-attack-data')
        .then(response => response.json())
        .then(data => {
            console.log('Data received:', data);

            // Update attack count
            document.getElementById('attack-count').innerText = data.attack_count;

            // Update the graph
            updateAttackChart(data.graph_data);

            // Update map with new attack locations
            updateMap(data.locations);

            // Play sound effect
            playSound();
        })
        .catch(error => console.error('Error:', error));
}

function updateMap(locations) {
    // Remove existing markers
    markers.forEach(marker => map.removeLayer(marker));
    markers = [];

    // Add new markers
    locations.forEach(location => {
        const { lat, lng, time, severity } = location;

        // Verify that lat and lng are within valid ranges
        if (lat >= -90 && lat <= 90 && lng >= -180 && lng <= 180) {
            const marker = L.marker([lat, lng])
                .addTo(map)
                .bindPopup(`Attack at ${time} - Severity: ${severity}`)
                .on('click', playSound); // Play sound when clicking a marker
            markers.push(marker);
        } else {
            console.error(`Invalid coordinates: ${lat}, ${lng}`);
        }
    });
}

function updateAttackChart(graphData) {
    if (attackChart) {
        attackChart.data.labels.push(graphData.time);
        attackChart.data.datasets[0].data.push(graphData.attacks);
        attackChart.update();
    } else {
        console.error('Chart not initialized!');
    }
}

function playSound() {
    if (attackSound) {
        attackSound.currentTime = 0; // Reset sound to start
        attackSound.play().then(() => {
            console.log('Sound played successfully.');
        }).catch(error => {
            console.error('Playback error:', error);
        });
    } else {
        console.error('Audio element not found!');
    }
}