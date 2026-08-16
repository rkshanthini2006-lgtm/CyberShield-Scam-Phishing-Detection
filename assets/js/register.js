/* ==========================================
   CYBERSHIELD - REGISTER
   Handles user registration
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    const registerName =
        document.getElementById("registerName");

    const registerEmail =
        document.getElementById("registerEmail");

    const registerPassword =
        document.getElementById("registerPassword");

    const confirmPassword =
        document.getElementById("confirmPassword");

    const registerButton =
        document.getElementById("registerButton");

    const registerStatus =
        document.getElementById("registerStatus");


    /* ==========================================
       REGISTER USER
    ========================================== */

    if (registerButton) {

        registerButton.addEventListener(
            "click",
            async () => {

                const name =
                    registerName.value.trim();

                const email =
                    registerEmail.value.trim();

                const password =
                    registerPassword.value;

                const confirm =
                    confirmPassword.value;


                /* ==========================================
                   BASIC VALIDATION
                ========================================== */

                if (!name) {

                    alert(
                        "Please enter your name."
                    );

                    return;

                }


                if (!email) {

                    alert(
                        "Please enter your email address."
                    );

                    return;

                }


                if (!password) {

                    alert(
                        "Please enter a password."
                    );

                    return;

                }


                if (password.length < 6) {

                    alert(
                        "Password must contain at least 6 characters."
                    );

                    return;

                }


                if (password !== confirm) {

                    alert(
                        "Passwords do not match."
                    );

                    return;

                }


                /* ==========================================
                   DISABLE BUTTON
                ========================================== */

                registerButton.disabled = true;

                const originalText =
                    registerButton.innerHTML;

                registerButton.innerHTML =
                    '<i class="fa-solid fa-spinner fa-spin"></i> Creating Account...';


                try {

                    /* ==========================================
                       SEND DATA TO BACKEND
                    ========================================== */

                    const response =
                        await fetch(
                            "/register",
                            {
                                method: "POST",

                                headers: {
                                    "Content-Type":
                                        "application/json"
                                },

                                body:
                                    JSON.stringify({

                                        name: name,

                                        email: email,

                                        password: password

                                    })

                            }
                        );


                    const result =
                        await response.json();


                    /* ==========================================
                       ERROR
                    ========================================== */

                    if (!response.ok) {

                        throw new Error(
                            result.error ||
                            "Registration failed."
                        );

                    }


                    /* ==========================================
                       SUCCESS
                    ========================================== */

                    if (registerStatus) {

                        registerStatus.textContent =
                            result.message ||
                            "Account created successfully.";

                        registerStatus.style.display =
                            "block";

                        registerStatus.style.color =
                            "#00E676";

                    }


                    /* Clear form */

                    registerName.value = "";

                    registerEmail.value = "";

                    registerPassword.value = "";

                    confirmPassword.value = "";


                }

                catch (error) {

                    console.error(
                        "CyberShield registration error:",
                        error
                    );


                    if (registerStatus) {

                        registerStatus.textContent =
                            error.message ||
                            "Unable to create account.";

                        registerStatus.style.display =
                            "block";

                        registerStatus.style.color =
                            "#FF4D4D";

                    }

                }

                finally {

                    registerButton.disabled =
                        false;

                    registerButton.innerHTML =
                        originalText;

                }

            }
        );

    }

});