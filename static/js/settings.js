// Helper function to save settings to localStorage
function saveToLocalStorage(key, value) {
    localStorage.setItem(key, JSON.stringify(value));
}

// Helper function to get settings from localStorage
function getFromLocalStorage(key) {
    const value = localStorage.getItem(key);
    return value ? JSON.parse(value) : null;
}

// Profile Picture Upload
document.getElementById('profile-pic').addEventListener('change', function(event) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const imageData = e.target.result;
            document.getElementById('profile-pic-preview').src = imageData;
            saveToLocalStorage('profile-pic', imageData);
        }
        reader.readAsDataURL(file);
    }
});

// Load saved profile picture
const savedProfilePic = getFromLocalStorage('profile-pic');
if (savedProfilePic) {
    document.getElementById('profile-pic-preview').src = savedProfilePic;
}

// Save Display Name
document.getElementById('save-display-name').addEventListener('click', function() {
    const displayName = document.getElementById('display-name').value;
    saveToLocalStorage('display-name', displayName);
    alert('Display name saved!');
});

// Load saved display name
const savedDisplayName = getFromLocalStorage('display-name');
if (savedDisplayName) {
    document.getElementById('display-name').value = savedDisplayName;
}

// Save Email
document.getElementById('save-email').addEventListener('click', function() {
    const email = document.getElementById('email').value;
    saveToLocalStorage('email', email);
    alert('Email saved!');
});

// Load saved email
const savedEmail = getFromLocalStorage('email');
if (savedEmail) {
    document.getElementById('email').value = savedEmail;
}

// Save Username
document.getElementById('save-username').addEventListener('click', function() {
    const username = document.getElementById('username').value;
    saveToLocalStorage('username', username);
    alert('Username saved!');
});

// Load saved username
const savedUsername = getFromLocalStorage('username');
if (savedUsername) {
    document.getElementById('username').value = savedUsername;
}

// Change Password
document.getElementById('save-password').addEventListener('click', function() {
    const password = document.getElementById('password').value;
    // Ensure you use proper methods to handle password securely
    saveToLocalStorage('password', password);
    alert('Password changed!');
});

// Load saved password (not recommended to show plain text password, handle it securely)
const savedPassword = getFromLocalStorage('password');
// Do not set password value in clear text, this is just a placeholder

// Save Privacy Settings
document.getElementById('save-privacy-settings').addEventListener('click', function() {
    const profileVisibility = document.getElementById('profile-visibility').value;
    saveToLocalStorage('profile-visibility', profileVisibility);
    alert('Privacy settings saved!');
});

// Load saved privacy settings
const savedPrivacySettings = getFromLocalStorage('profile-visibility');
if (savedPrivacySettings) {
    document.getElementById('profile-visibility').value = savedPrivacySettings;
}

// Apply Theme
document.getElementById('apply-theme').addEventListener('click', function() {
    const theme = document.getElementById('theme-select').value;
    document.body.setAttribute('data-theme', theme); // Apply theme via data attribute
    saveToLocalStorage('theme', theme); // Save theme to localStorage
    alert('Theme applied: ' + theme);
});

// Load saved theme
const savedTheme = getFromLocalStorage('theme');
if (savedTheme) {
    document.getElementById('theme-select').value = savedTheme;
    document.body.setAttribute('data-theme', savedTheme); // Apply saved theme
}

// Save Security Settings
document.getElementById('save-security-settings').addEventListener('click', function() {
    const twoFactorAuth = document.getElementById('two-factor-auth').checked;
    saveToLocalStorage('two-factor-auth', twoFactorAuth);
    alert('Security settings saved! 2FA: ' + (twoFactorAuth ? 'Enabled' : 'Disabled'));
});

// Load saved security settings
const savedTwoFactorAuth = getFromLocalStorage('two-factor-auth');
if (savedTwoFactorAuth !== null) {
    document.getElementById('two-factor-auth').checked = savedTwoFactorAuth;
}

// Delete Account
document.getElementById('delete-account').addEventListener('click', function() {
    if (confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
        // Clear all settings from localStorage
        localStorage.clear();
        alert('Account deleted!');
        // Redirect or perform additional actions here
    }
});
