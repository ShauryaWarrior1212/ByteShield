document.getElementById('scan-button').addEventListener('click', function(event) {
    event.preventDefault(); // Prevent form submission
    const url = document.getElementById('url').value;

    // Check if URL input is not empty
    if (!url) {
        document.getElementById('result').textContent = 'Please enter a URL.';
        return;
    }

    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        console.log('API Response:', data); // Debug: Log the API response
        if (data.safe !== undefined) {
            document.getElementById('result').textContent = data.safe ? 'Site is safe!' : 'Site is not safe.';
        } else if (data.error) {
            document.getElementById('result').textContent = 'Error: ' + data.error;
        } else {
            document.getElementById('result').textContent = 'Unexpected response.';
        }
    })
    .catch(error => {
        document.getElementById('result').textContent = 'An error occurred. Please try again.';
        console.error('Error:', error);
    });
});
