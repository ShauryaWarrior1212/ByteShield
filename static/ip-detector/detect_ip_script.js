document.addEventListener('DOMContentLoaded', function() {
    const bgVideo = document.getElementById('bgVideo');
    const resultDiv = document.getElementById('detectResult');
    const overlay = document.getElementById('overlay');
    const infoBox = document.getElementById('infoBox');
    const detectBtn = document.getElementById('detectBtn');

    if (bgVideo) {
        bgVideo.play().catch(error => {
            console.error('Video playback failed:', error);
        });
    }

    detectBtn.addEventListener('click', function() {
        detectBtn.disabled = true;

        fetch('/detect_ip')
            .then(response => response.json())
            .then(data => {
                detectBtn.style.display = 'none';
                overlay.style.display = 'flex';

                // Display the IP details including ISP
                infoBox.innerHTML = `
                    <p>IP Address: ${data.IP}</p>
                    <p>City: ${data.City}</p>
                    <p>Region: ${data.Region}</p>
                    <p>Country: ${data.Country}</p>
                    <p>Timezone: ${data.Timezone}</p>
                    <p>ISP: ${data.ISP}</p> <!-- Added ISP -->
                `;
            })
            .catch(error => {
                resultDiv.innerHTML = `<p>Error fetching IP details.</p>`;
                console.error('Fetch error:', error);

                detectBtn.disabled = false;
                overlay.style.display = 'none';
            });
    });
});
