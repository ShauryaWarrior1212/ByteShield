document.getElementById('trackBtn').addEventListener('click', function() {
    const ip = document.getElementById('ipInput').value;
    const resultDiv = document.getElementById('result');

    if (ip === '') {
        resultDiv.innerHTML = '<p>Please enter a valid IP address.</p>';
        return;
    }

    fetch('/track_ip', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: new URLSearchParams({
            'ip': ip
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            resultDiv.innerHTML = `<p>Error: ${data.error}</p>`;
        } else {
            resultDiv.innerHTML = `
                <p><strong>IP:</strong> ${data.IP}</p>
                <p><strong>City:</strong> ${data.City}</p>
                <p><strong>Region:</strong> ${data.Region}</p>
                <p><strong>Country:</strong> ${data.Country}</p>
                <p><strong>Country Code:</strong> ${data['Country Code']}</p>
                <p><strong>Timezone:</strong> ${data.Timezone}</p>
                <p><strong>ISP:</strong> ${data.ISP}</p>
                <p><strong>Org:</strong> ${data.Org}</p>
                <p><strong>AS:</strong> ${data.AS}</p>
            `;

            const map = L.map('map').setView([data.Lat, data.Lon], 13);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                maxZoom: 19,
            }).addTo(map);
            L.marker([data.Lat, data.Lon]).addTo(map)
                .bindPopup(`<b>${data.City}, ${data.Region}</b><br>${data.Country}`)
                .openPopup();
        }
    })
    .catch(error => {
        resultDiv.innerHTML = `<p>Error: ${error}</p>`;
    });
});
