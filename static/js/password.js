function checkPassword() {
    const password = document.getElementById("password").value;
    const strengthBar = document.getElementById("strength");
    const message = document.getElementById("message");

    const criteria = {
        length: password.length >= 12,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[@$!%*?&#]/.test(password),
        noRepeat: !/(.)\1{2,}/.test(password),
        uncommon: !/^(123456|password|qwerty)$/.test(password.toLowerCase()),
        veryLong: password.length >= 14
    };

    let strength = 0;
    for (let key in criteria) {
        if (criteria[key]) strength += 1;
    }

    // Update the strength bar
    strengthBar.className = "strength-bar";
    const strengthPercentage = (strength / Object.keys(criteria).length) * 100;
    strengthBar.style.width = strengthPercentage + "%";

    // Update the color of the strength bar
    const colors = ["red", "orange", "yellow", "lightgreen", "green"];
    strengthBar.style.backgroundColor = colors[Math.min(4, Math.floor(strengthPercentage / 25))];

    // Update the message based on the strength
    let strengthLevel;
    if (strength >= 7) {
        strengthLevel = "Very Strong";
    } else if (strength >= 5) {
        strengthLevel = "Strong";
    } else if (strength >= 3) {
        strengthLevel = "Medium";
    } else if (strength >= 1) {
        strengthLevel = "Weak";
    } else {
        strengthLevel = "Very Weak";
    }
    message.innerHTML = strengthLevel;

    // Check and display which criteria are met
    const criteriaMessages = [];
    if (!criteria.length) criteriaMessages.push("At least 12 characters");
    if (!criteria.uppercase) criteriaMessages.push("At least one uppercase letter");
    if (!criteria.lowercase) criteriaMessages.push("At least one lowercase letter");
    if (!criteria.number) criteriaMessages.push("At least one number");
    if (!criteria.special) criteriaMessages.push("At least one special character");
    if (!criteria.noRepeat) criteriaMessages.push("Avoid repeating characters");
    if (!criteria.uncommon) criteriaMessages.push("Avoid common patterns or passwords");
    if (!criteria.veryLong) criteriaMessages.push("Consider using 14+ characters for extra strength");

    if (criteriaMessages.length > 0) {
        message.innerHTML += "<br>Consider adding:<br>" + criteriaMessages.join("<br>");
    }

    // Add glowing effect for maximum strength
    if (strength === Object.keys(criteria).length) {
        strengthBar.classList.add("glow");
    } else {
        strengthBar.classList.remove("glow");
    }
}
