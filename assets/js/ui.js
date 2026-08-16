/* ==========================================
   CyberShield UI JavaScript
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ======================================
       Scroll To Top Button
    ====================================== */

    const scrollButton = document.createElement("button");

    scrollButton.innerHTML = "↑";

    scrollButton.id = "scrollTopBtn";

    document.body.appendChild(scrollButton);

    scrollButton.style.position = "fixed";
    scrollButton.style.bottom = "30px";
    scrollButton.style.right = "30px";
    scrollButton.style.width = "50px";
    scrollButton.style.height = "50px";
    scrollButton.style.borderRadius = "50%";
    scrollButton.style.border = "none";
    scrollButton.style.cursor = "pointer";
    scrollButton.style.background = "#00C2FF";
    scrollButton.style.color = "#fff";
    scrollButton.style.fontSize = "22px";
    scrollButton.style.display = "none";
    scrollButton.style.zIndex = "999";

    window.addEventListener("scroll", () => {

        if(window.scrollY > 300){

            scrollButton.style.display = "block";

        }

        else{

            scrollButton.style.display = "none";

        }

    });

    scrollButton.addEventListener("click", () => {

        window.scrollTo({

            top:0,

            behavior:"smooth"

        });

    });

    /* ======================================
       Loading Animation
    ====================================== */

    window.addEventListener("load", () => {

        document.body.style.opacity = "1";

    });

    document.body.style.opacity = "0";

    document.body.style.transition = "opacity .6s ease";

    /* ======================================
       Button Ripple Effect
    ====================================== */

    const buttons = document.querySelectorAll(".primary-btn,.scan-btn");

    buttons.forEach(button => {

        button.addEventListener("click", function(){

            this.style.transform = "scale(.96)";

            setTimeout(()=>{

                this.style.transform = "scale(1)";

            },150);

        });

    });

});