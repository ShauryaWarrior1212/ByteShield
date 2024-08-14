function checkPassword() {
    const password = document.getElementById("password").value;
    const strengthBar = document.getElementById("strength");
    const message = document.getElementById("message");

    const criteria = {
        length: password.length >= 8,
        uppercase: /[A-Z]/.test(password),
        number: /[0-9]/.test(password),
        special: /[@$!%*?&#]/.test(password),
        lowercase: /[a-z]/.test(password)
    };

    let strength = 0;
    for (let key in criteria) {
        if (criteria[key]) strength += 1;
    }

    // Update the strength bar based on the calculated strength
    strengthBar.className = "strength-bar";
    strengthBar.style.width = strength * 20 + "%";
    
    // Set the color of the strength bar based on the strength
    const colors = ["red", "orange", "yellow", "lightgreen", "green"];
    strengthBar.style.backgroundColor = colors[strength - 1];

    // Update the message based on the strength
    const messages = ["Very Weak", "Weak", "Medium", "Strong", "Very Strong"];
    message.textContent = messages[strength - 1] || "Invalid password";

    // Check and display which criteria are met
    const criteriaMessages = [];
    if (!criteria.length) criteriaMessages.push("At least 8 characters");
    if (!criteria.uppercase) criteriaMessages.push("At least one uppercase letter");
    if (!criteria.lowercase) criteriaMessages.push("At least one lowercase letter");
    if (!criteria.number) criteriaMessages.push("At least one number");
    if (!criteria.special) criteriaMessages.push("At least one special character");

    if (criteriaMessages.length > 0) {
        message.innerHTML += "<br>Consider adding:<br>" + criteriaMessages.join("<br>");
    }

    if (strength == 5) {
        strengthBar.classList.add("glow");
    } else {
        strengthBar.classList.remove("glow");
    }
}
