/* ==========================================
   CYBERSHIELD - LOGIN
   Handles user login
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    const loginEmail =
        document.getElementById("loginEmail");

    const loginPassword =
        document.getElementById("loginPassword");

    const loginButton =
        document.getElementById("loginButton");

    const loginStatus =
        document.getElementById("loginStatus");


    /* ==========================================
       LOGIN
    ========================================== */

    if (!loginButton) {

        console.error(
            "CyberShield: Login button not found."
        );

        return;

    }


    loginButton.addEventListener(
        "click",
        async () => {

            const email =
                loginEmail.value.trim();

            const password =
                loginPassword.value;


            /* ==========================================
               BASIC VALIDATION
            ========================================== */

            if (!email) {

                alert(
                    "Please enter your email address."
                );

                return;

            }


            if (!password) {

                alert(
                    "Please enter your password."
                );

                return;

            }


            /* ==========================================
               DISABLE BUTTON
            ========================================== */

            loginButton.disabled = true;

            const originalText =
                loginButton.innerHTML;

            loginButton.innerHTML =
                '<i class="fa-solid fa-spinner fa-spin"></i> Logging in...';


            try {

                /* ==========================================
                   SEND LOGIN REQUEST
                ========================================== */

                const response =
                    await fetch(
                        "/login",
                        {
                            method: "POST",

                            headers: {
                                "Content-Type":
                                    "application/json"
                            },

                            body:
                                JSON.stringify({

                                    email: email,

                                    password: password

                                })
                        }
                    );


                /* ==========================================
                   READ SERVER RESPONSE
                ========================================== */

                const responseText =
                    await response.text();

                console.log(
                    "Login HTTP Status:",
                    response.status
                );

                console.log(
                    "Login Server Response:",
                    responseText
                );


                let result;

                try {

                    result =
                        JSON.parse(responseText);

                }

                catch (jsonError) {

                    throw new Error(
                        "Server returned an invalid response. Check the Flask terminal."
                    );

                }


                /* ==========================================
                   BACKEND ERROR
                ========================================== */

                if (!response.ok) {

                    throw new Error(
                        result.error ||
                        result.message ||
                        `Login failed. HTTP ${response.status}`
                    );

                }


                /* ==========================================
                   CHECK USER DATA
                ========================================== */

                if (
                    !result.user ||
                    !result.user.id
                ) {

                    throw new Error(
                        "Login succeeded, but user information was not returned by the server."
                    );

                }


                /* ==========================================
                   STORE USER INFORMATION
                ========================================== */

                localStorage.setItem(
                    "user_id",
                    String(result.user.id)
                );

                localStorage.setItem(
                    "user_name",
                    result.user.name || ""
                );

                localStorage.setItem(
                    "user_email",
                    result.user.email || ""
                );


                console.log(
                    "Logged-in User:",
                    result.user
                );


                /* ==========================================
                   SUCCESS MESSAGE
                ========================================== */

                if (loginStatus) {

                    loginStatus.textContent =
                        result.message ||
                        "Login successful.";

                    loginStatus.style.display =
                        "block";

                    loginStatus.style.color =
                        "#00E676";

                }


                /* ==========================================
                   REDIRECT
                ========================================== */

                setTimeout(() => {

                    window.location.href =
                        "/dashboard.html";

                }, 800);

            }


            /* ==========================================
               LOGIN ERROR
            ========================================== */

            catch (error) {

                console.error(
                    "CyberShield login error:",
                    error
                );


                if (loginStatus) {

                    loginStatus.textContent =
                        error.message ||
                        "Unable to login.";

                    loginStatus.style.display =
                        "block";

                    loginStatus.style.color =
                        "#FF4D4D";

                }

            }


            /* ==========================================
               ENABLE BUTTON AGAIN
            ========================================== */

            finally {

                loginButton.disabled =
                    false;

                loginButton.innerHTML =
                    originalText;

            }

        }
    );

});