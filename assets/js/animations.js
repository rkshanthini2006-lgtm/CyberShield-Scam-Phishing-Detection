/* ==========================================
   CyberShield Animation JavaScript
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ======================================
       Scroll Reveal Animation
    ====================================== */

    const revealElements = document.querySelectorAll(

        ".feature-card, .stat-card, .step, .scanner-box, .testimonial-card, .faq-item, .contact-container"

    );

    const revealOnScroll = () => {

        const triggerBottom = window.innerHeight * 0.85;

        revealElements.forEach(element => {

            const elementTop = element.getBoundingClientRect().top;

            if (elementTop < triggerBottom) {

                element.style.opacity = "1";

                element.style.transform = "translateY(0)";

            }

        });

    };

    revealElements.forEach(element => {

        element.style.opacity = "0";

        element.style.transform = "translateY(40px)";

        element.style.transition = "all 0.8s ease";

    });

    window.addEventListener("scroll", revealOnScroll);

    revealOnScroll();

    /* ======================================
       Statistics Counter Animation
    ====================================== */

    const counters = document.querySelectorAll(".stat-card h2");

    counters.forEach(counter => {

        const targetText = counter.innerText;

        const target = parseInt(targetText.replace(/\D/g, ""));

        if (isNaN(target)) return;

        let count = 0;

        const speed = Math.max(20, target / 100);

        const updateCounter = () => {

            if (count < target) {

                count += speed;

                counter.innerText = Math.ceil(count);

                if (targetText.includes("%")) {

                    counter.innerText += "%";

                } else if (targetText.includes("K")) {

                    counter.innerText += "K+";

                } else {

                    counter.innerText += "+";

                }

                requestAnimationFrame(updateCounter);

            } else {

                counter.innerText = targetText;

            }

        };

        updateCounter();

    });

});