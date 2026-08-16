document.addEventListener("DOMContentLoaded", function () {

    const scanButton = document.querySelector("#analyzeButton");
    const scanType = document.querySelector("#scanType");
    const scanInput = document.querySelector("#scanInput");

    const scanResult = document.querySelector("#scanResult");
    const resultRisk = document.querySelector("#resultRisk");
    const resultScore = document.querySelector("#resultScore");
    const resultReasons = document.querySelector("#resultReasons");

    console.log("CyberShield scanner loaded");
    console.log("Scan button:", scanButton);
    console.log("Scan type:", scanType);
    console.log("Scan input:", scanInput);
    console.log("Scan result:", scanResult);

    if (
        !scanButton ||
        !scanType ||
        !scanInput ||
        !scanResult ||
        !resultRisk ||
        !resultScore ||
        !resultReasons
    ) {
        console.error("CyberShield scanner elements not found.");
        return;
    }


    /* ==========================================
       CLOSE RESULT
    ========================================== */

    function closeResult() {

        scanResult.style.display = "none";

        document.body.classList.remove("scanner-result-open");

    }


    /* ==========================================
       SHOW RESULT
    ========================================== */

    function showResult(result) {

        resultRisk.textContent = result.risk;
        resultScore.textContent = result.score + "/100";

        /* Remove old risk classes */

        scanResult.classList.remove(
            "safe",
            "suspicious",
            "dangerous"
        );


        /* Add current risk class */

        const riskClass = String(result.risk)
            .toLowerCase()
            .trim();

        if (
            riskClass === "safe" ||
            riskClass === "suspicious" ||
            riskClass === "dangerous"
        ) {

            scanResult.classList.add(riskClass);

        }


        /* Clear previous reasons */

        resultReasons.innerHTML = "";


        /* Add reasons */

        if (
            result.reasons &&
            result.reasons.length > 0
        ) {

            result.reasons.forEach(function (reason) {

                const li = document.createElement("li");

                li.textContent = reason;

                resultReasons.appendChild(li);

            });

        } else {

            const li = document.createElement("li");

            li.textContent =
                "No suspicious indicators found.";

            resultReasons.appendChild(li);

        }


        /* Show result */

        scanResult.style.display = "block";

        document.body.classList.add("scanner-result-open");

    }


    /* ==========================================
       SCAN BUTTON
    ========================================== */

    scanButton.addEventListener(
        "click",
        async function () {

            const type = scanType.value;

            const input = scanInput.value.trim();


            /* Empty input */

            if (input === "") {

                alert(
                    "Please enter something to analyze."
                );

                return;

            }


            /* Button loading state */

            scanButton.textContent = "Analyzing...";

            scanButton.disabled = true;


            try {

                let endpoint = "";

                let body = {};


                /* =========================
                   URL SCAN
                ========================= */

                if (type === "url") {

                    endpoint =
                        "http://127.0.0.1:5000/scan";

                    body = {
                        url: input
                    };

                }


                /* =========================
                   MESSAGE SCAN
                ========================= */

                else if (type === "message") {

                    endpoint =
                        "http://127.0.0.1:5000/scan-message";

                    body = {
                        message: input
                    };

                }


                /* =========================
                   EMAIL SCAN
                ========================= */

                else if (type === "email") {

                    endpoint =
                        "http://127.0.0.1:5000/scan-email";

                    body = {
                        email: input
                    };

                }


                /* =========================
                   BACKEND REQUEST
                ========================= */

                const response = await fetch(
                    endpoint,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify(body)
                    }
                );


                const result =
                    await response.json();


                /* Backend error */

                if (!response.ok) {

                    throw new Error(
                        result.error ||
                        "Scan failed"
                    );

                }


                /* =========================
                   DISPLAY RESULT
                ========================= */

                showResult(result);

            }


            catch (error) {

                console.error(
                    "CyberShield scanner error:",
                    error
                );

                alert(
                    "Cannot connect to CyberShield backend."
                );

            }


            finally {

                scanButton.textContent =
                    "Analyze Now";

                scanButton.disabled = false;

            }

        }
    );


    /* ==========================================
       CLOSE WHEN CLICKING OUTSIDE RESULT
    ========================================== */

    scanResult.addEventListener(
        "click",
        function (event) {

            if (
                event.target === scanResult
            ) {

                closeResult();

            }

        }
    );


    /* ==========================================
       ESC KEY CLOSE
    ========================================== */

    document.addEventListener(
        "keydown",
        function (event) {

            if (
                event.key === "Escape"
            ) {

                closeResult();

            }

        }
    );

});