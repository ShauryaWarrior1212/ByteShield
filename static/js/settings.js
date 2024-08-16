document.addEventListener('DOMContentLoaded', () => {
    // Load settings from local storage
    const savedDisplayName = localStorage.getItem('displayName');
    const savedProfilePic = localStorage.getItem('profilePic');
    const savedTheme = localStorage.getItem('theme');
    const emailNotifications = localStorage.getItem('emailNotifications') === 'true';
    const pushNotifications = localStorage.getItem('pushNotifications') === 'true';
    const profileVisibility = localStorage.getItem('profileVisibility') || 'public';
    const twoFactorAuth = localStorage.getItem('twoFactorAuth') === 'true';

    if (savedDisplayName) {
        document.getElementById('display-name').value = savedDisplayName;
    }
    if (savedProfilePic) {
        document.getElementById('profile-pic-preview').src = savedProfilePic;
    }
    if (savedTheme) {
        document.getElementById('theme-stylesheet').setAttribute('href', `static/css/${savedTheme}-theme.css`);
        document.getElementById('theme-select').value = savedTheme;
    }
    document.getElementById('email-notifications').checked = emailNotifications;
    document.getElementById('push-notifications').checked = pushNotifications;
    document.getElementById('profile-visibility').value = profileVisibility;
    document.getElementById('two-factor-auth').checked = twoFactorAuth;

    // Save settings
    document.getElementById('save-display-name').addEventListener('click', () => {
        const displayName = document.getElementById('display-name').value;
        localStorage.setItem('displayName', displayName);
        alert('Display Name saved!');
    });

    document.getElementById('upload-pic').addEventListener('click', () => {
        const fileInput = document.getElementById('profile-pic');
        if (fileInput.files.length > 0) {
            const file = fileInput.files[0];
            const reader = new FileReader();
            reader.onloadend = () => {
                const profilePic = reader.result;
                document.getElementById('profile-pic-preview').src = profilePic;
                localStorage.setItem('profilePic', profilePic);
                alert('Profile Picture uploaded!');
            };
            reader.readAsDataURL(file);
        }
    });

    document.getElementById('save-email').addEventListener('click', () => {
        const email = document.getElementById('email').value;
        localStorage.setItem('email', email);
        alert('Email saved!');
    });

    document.getElementById('save-username').addEventListener('click', () => {
        const username = document.getElementById('username').value;
        localStorage.setItem('username', username);
        alert('Username saved!');
    });

    document.getElementById('save-password').addEventListener('click', () => {
        const password = document.getElementById('password').value;
        localStorage.setItem('password', password);
        alert('Password changed!');
    });

    document.getElementById('email-notifications').addEventListener('change', (e) => {
        localStorage.setItem('emailNotifications', e.target.checked);
    });

    document.getElementById('push-notifications').addEventListener('change', (e) => {
        localStorage.setItem('pushNotifications', e.target.checked);
    });

    document.getElementById('save-privacy-settings').addEventListener('click', () => {
        const profileVisibility = document.getElementById('profile-visibility').value;
        localStorage.setItem('profileVisibility', profileVisibility);
        alert('Privacy settings saved!');
    });

    document.getElementById('apply-theme').addEventListener('click', () => {
        const theme = document.getElementById('theme-select').value;
        const stylesheet = document.getElementById('theme-stylesheet');
        stylesheet.setAttribute('href', `static/css/${theme}-theme.css`);
        localStorage.setItem('theme', theme);
    });

    document.getElementById('save-security-settings').addEventListener('click', () => {
        const twoFactorAuth = document.getElementById('two-factor-auth').checked;
        localStorage.setItem('twoFactorAuth', twoFactorAuth);
        alert('Security settings saved!');
    });

    document.getElementById('delete-account').addEventListener('click', () => {
        if (confirm('Are you sure you want to delete your account? This action cannot be undone.')) {
            // Add account deletion logic here
            alert('Account deleted!');
        }
    });
});

// Apply theme
document.getElementById('apply-theme').addEventListener('click', () => {
    const theme = document.getElementById('theme-select').value;
    const stylesheet = document.getElementById('theme-stylesheet');
    stylesheet.setAttribute('href', `static/css/${theme}-theme.css`);
    localStorage.setItem('theme', theme);
});