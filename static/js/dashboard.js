$(document).ready(function() {
    // Assuming menu toggle functionality
    $(".menuToggle").click(function() {
        $(".menu").toggleClass("active");
    });

    // Check for any other JS conflicts
    var toggleSound = $("#toggleSound")[0];
    var openSound = $("#openSound")[0];
    var hoverSound = $("#hoverSound")[0];

    let menuToggle = document.querySelector(".menuToggle");
    let menu = document.querySelector(".menu");

    menuToggle.onclick = function () {
        menu.classList.toggle("active");
        toggleSound.currentTime = 0; // Reset the audio to start from the beginning
        toggleSound.play();
        if (menu.classList.contains("active")) {
            openSound.currentTime = 0; // Reset the audio to start from the beginning
            openSound.play();
        }
    };

    $(".menu a").hover(function() {
        hoverSound.currentTime = 0; // Reset the audio to start from the beginning
        hoverSound.play();
    });
});
