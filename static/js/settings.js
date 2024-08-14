document.addEventListener('DOMContentLoaded', function() {
    const themeSelector = document.getElementById('themeSelector');
    const themePreview = document.getElementById('themePreview');
    const profilePictureInput = document.getElementById('profilePicture');
    const profilePicturePreview = document.getElementById('profilePicturePreview');

    // Apply theme change and preview
    themeSelector.addEventListener('change', function() {
        const selectedTheme = this.value;
        document.body.className = selectedTheme;
        localStorage.setItem('theme', selectedTheme); // Save theme preference
        updateThemePreview(selectedTheme);
    });

    // Load saved theme and update preview
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.body.className = savedTheme;
    themeSelector.value = savedTheme;
    updateThemePreview(savedTheme);

    function updateThemePreview(theme) {
        themePreview.style.backgroundColor = getComputedStyle(document.body).backgroundColor;
        themePreview.style.color = getComputedStyle(document.body).color;
    }

    // Handle profile picture upload
    profilePictureInput.addEventListener('change', function() {
        const file = this.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                profilePicturePreview.src = e.target.result;
            };
            reader.readAsDataURL(file);
        }
    });
});
