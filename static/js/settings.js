document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('settings-form');

    form.addEventListener('submit', function(event) {
        event.preventDefault();
        
        const username = document.getElementById('username').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm-password').value;

        if (password && password !== confirmPassword) {
            alert('Passwords do not match!');
            return;
        }

        // Simulate form submission
        alert('Settings saved successfully!');
        form.reset();
    });
});
