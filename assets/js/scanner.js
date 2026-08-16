/* ==========================================
   CYBERSHIELD - SCANNER
   Handles URL, message and email scanning
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    const scanType = document.getElementById("scanType");
    const scanInput = document.getElementById("scanInput");
    const analyzeButton = document.getElementById("analyzeButton");

    const scanResult = document.getElementById("scanResult");
    const closeScanResult = document.getElementById("closeScanResult");

    const resultRisk = document.getElementById("resultRisk");
    const resultScore = document.getElementById("resultScore");
    const resultReasons = document.getElementById("resultReasons");


    /* ==========================================
       PLACEHOLDER TEXT
    ========================================== */

    function updatePlaceholder() {

        if (!scanType || !scanInput) {
            return;
        }

        if (scanType.value === "url") {

            scanInput.placeholder =
                "Paste a suspicious URL here...";

        }

        else if (scanType.value === "message") {

            scanInput.placeholder =
                "Paste a suspicious message here...";

        }

        else if (scanType.value === "email") {

            scanInput.placeholder =
                "Paste suspicious email content here...";

        }

    }


    if (scanType) {

        scanType.addEventListener(
            "change",
            updatePlaceholder
        );

    }


    updatePlaceholder();


    /* ==========================================
       OPEN SCAN RESULT
    ========================================== */

    function openScanResult(result) {

        if (!scanResult) {
            return;
        }

        resultRisk.textContent =
            result.risk || "Unknown";

        resultScore.textContent =
            `${result.score ?? 0}/100`;


        resultReasons.innerHTML = "";


        if (
            result.reasons &&
            result.reasons.length > 0
        ) {

            result.reasons.forEach(reason => {

                const li =
                    document.createElement("li");

                li.textContent = reason;

                resultReasons.appendChild(li);

            });

        }

        else {

            const li =
                document.createElement("li");

            li.textContent =
                "No suspicious indicators found.";

            resultReasons.appendChild(li);

        }


        /* Remove previous risk classes */

        scanResult.classList.remove(
            "safe",
            "suspicious",
            "dangerous"
        );


        /* Add current risk class */

        const risk =
            String(result.risk || "")
                .toLowerCase();


        if (risk === "safe") {

            scanResult.classList.add("safe");

        }

        else if (risk === "suspicious") {

            scanResult.classList.add("suspicious");

        }

        else if (risk === "dangerous") {

            scanResult.classList.add("dangerous");

        }


        /* Open modal */

        scanResult.style.display = "block";

        document.body.classList.add(
            "scanner-result-open"
        );

    }


    /* ==========================================
       CLOSE SCAN RESULT
    ========================================== */

    function closeResult() {

        if (!scanResult) {
            return;
        }

        scanResult.style.display = "none";

        scanResult.classList.remove(
            "safe",
            "suspicious",
            "dangerous"
        );

        document.body.classList.remove(
            "scanner-result-open"
        );

    }


    /* ==========================================
       CLOSE BUTTON
    ========================================== */

    if (closeScanResult) {

        closeScanResult.addEventListener(
            "click",
            function (event) {

                event.preventDefault();
                event.stopPropagation();

                closeResult();

            }
        );

    }


    /* ==========================================
       ESCAPE KEY
    ========================================== */

    document.addEventListener(
        "keydown",
        event => {

            if (
                event.key === "Escape" &&
                scanResult &&
                scanResult.style.display !== "none"
            ) {

                closeResult();

            }

        }
    );


    /* ==========================================
       ANALYZE
    ========================================== */

    if (analyzeButton) {

        analyzeButton.addEventListener(
            "click",
            async () => {

                const input =
                    scanInput.value.trim();

                if (!input) {

                    alert(
                        "Please enter something to scan."
                    );

                    return;

                }


                /* ==========================================
                   GET LOGGED-IN USER ID
                ========================================== */

                const userId =
                    localStorage.getItem("user_id");


                if (!userId) {

                    alert(
                        "Please login before scanning."
                    );

                    return;

                }


                /* Disable button */

                analyzeButton.disabled = true;

                const originalText =
                    analyzeButton.textContent;

                analyzeButton.textContent =
                    "Analyze Now";


                try {

                    let endpoint = "";

                    let payload = {};


                    /* URL */

                    if (scanType.value === "url") {

                        endpoint =
                            "/scan";

                        payload = {
                            url: input
                        };

                    }


                    /* MESSAGE */

                    else if (
                        scanType.value === "message"
                    ) {

                        endpoint =
                            "/scan-message";

                        payload = {
                            message: input
                        };

                    }


                    /* EMAIL */

                    else if (
                        scanType.value === "email"
                    ) {

                        endpoint =
                            "/scan-email";

                        payload = {
                            email: input
                        };

                    }


                    /* ==========================================
                       SEND SCAN REQUEST
                    ========================================== */

                    const response =
                        await fetch(
                            endpoint,
                            {
                                method: "POST",

                                headers: {

                                    "Content-Type":
                                        "application/json",

                                    "X-User-ID":
                                        userId

                                },

                                body:
                                    JSON.stringify(
                                        payload
                                    )
                            }
                        );


                    const result =
                        await response.json();


                    if (!response.ok) {

                        throw new Error(
                            result.error ||
                            "Scan failed."
                        );

                    }


                    openScanResult(result);

                }

                catch (error) {

                    console.error(
                        "CyberShield scan error:",
                        error
                    );

                    alert(
                        error.message ||
                        "Unable to complete the scan."
                    );

                }

                finally {

                    analyzeButton.disabled =
                        false;

                    analyzeButton.textContent =
                        originalText;

                }

            }
        );

    }

});