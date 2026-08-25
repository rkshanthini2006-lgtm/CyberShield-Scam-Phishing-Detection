/* ==========================================
   CYBERSHIELD - SCANNER
   Handles URL, message and email scanning
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    const scanType =
        document.getElementById("scanType");

    const scanInput =
        document.getElementById("scanInput");

    const analyzeButton =
        document.getElementById("analyzeButton");

    const scanResult =
        document.getElementById("scanResult");

    const closeScanResult =
        document.getElementById("closeScanResult");

    const resultRisk =
        document.getElementById("resultRisk");

    const resultScore =
        document.getElementById("resultScore");

    const resultReasons =
        document.getElementById("resultReasons");


    /* ==========================================
       UPDATE PLACEHOLDER
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


    /* ==========================================
       SCAN TYPE CHANGE
    ========================================== */

    if (scanType) {

        scanType.addEventListener(
            "change",
            updatePlaceholder
        );

    }


    updatePlaceholder();


    /* ==========================================
       RESET SCANNER
    ========================================== */

    function resetScanner() {

        /* Clear input */

        if (scanInput) {

            scanInput.value = "";

        }


        /* Reset scan type */

        if (scanType) {

            scanType.value = "url";

        }


        /* Restore placeholder */

        updatePlaceholder();


        /* Restore Analyze button */

        if (analyzeButton) {

            analyzeButton.disabled = false;

            analyzeButton.textContent =
                "Analyze Now";

        }


        /* Clear result content */

        if (resultRisk) {

            resultRisk.textContent = "-";

        }


        if (resultScore) {

            resultScore.textContent = "-";

        }


        if (resultReasons) {

            resultReasons.innerHTML = "";

        }


        /* Hide result */

        if (scanResult) {

            scanResult.style.display = "none";

            scanResult.classList.remove(
                "safe",
                "suspicious",
                "dangerous"
            );

        }


        /* Remove scanner-result-open state */

        document.body.classList.remove(
            "scanner-result-open"
        );

    }


    /* ==========================================
       OPEN SCAN RESULT
    ========================================== */

    function openScanResult(result) {

        if (!scanResult) {
            return;
        }


        /* --------------------------------------
           RISK
        -------------------------------------- */

        if (resultRisk) {

            resultRisk.textContent =
                result.risk || "Unknown";

        }


        /* --------------------------------------
           SCORE
        -------------------------------------- */

        if (resultScore) {

            resultScore.textContent =
                `${result.score ?? 0}/100`;

        }


        /* --------------------------------------
           REASONS
        -------------------------------------- */

        if (resultReasons) {

            resultReasons.innerHTML = "";


            const reasons =
                Array.isArray(result.reasons)
                    ? result.reasons
                    : (
                        result.reasons
                            ? [result.reasons]
                            : []
                    );


            if (reasons.length > 0) {

                reasons.forEach(
                    reason => {

                        const li =
                            document.createElement(
                                "li"
                            );

                        li.textContent =
                            reason;

                        resultReasons.appendChild(
                            li
                        );

                    }
                );

            }

            else {

                const li =
                    document.createElement(
                        "li"
                    );

                li.textContent =
                    "No suspicious indicators found.";

                resultReasons.appendChild(
                    li
                );

            }

        }


        /* --------------------------------------
           REMOVE OLD RISK CLASSES
        -------------------------------------- */

        scanResult.classList.remove(
            "safe",
            "suspicious",
            "dangerous"
        );


        /* --------------------------------------
           APPLY CURRENT RISK CLASS
        -------------------------------------- */

        const risk =
            String(
                result.risk || ""
            ).toLowerCase();


        if (risk === "safe") {

            scanResult.classList.add(
                "safe"
            );

        }

        else if (risk === "suspicious") {

            scanResult.classList.add(
                "suspicious"
            );

        }

        else if (risk === "dangerous") {

            scanResult.classList.add(
                "dangerous"
            );

        }


        /* --------------------------------------
           SHOW RESULT
        -------------------------------------- */

        scanResult.style.display =
            "block";

        document.body.classList.add(
            "scanner-result-open"
        );


        /* --------------------------------------
           IMPORTANT:
           BUTTON MUST NOT REMAIN IN LOADING STATE
        -------------------------------------- */

        if (analyzeButton) {

            analyzeButton.disabled =
                false;

            analyzeButton.textContent =
                "Analyze Now";

        }

    }


    /* ==========================================
       CLOSE RESULT
    ========================================== */

    function closeResult() {

        /*
         * When the user closes the result,
         * completely reset the scanner.
         */

        resetScanner();

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
                    scanInput
                        ? scanInput.value.trim()
                        : "";


                /* --------------------------------
                   EMPTY INPUT
                -------------------------------- */

                if (!input) {

                    alert(
                        "Please enter something to scan."
                    );

                    return;

                }


                /* --------------------------------
                   LOGIN CHECK
                -------------------------------- */

                const userId =
                    localStorage.getItem(
                        "user_id"
                    );


                if (!userId) {

                    alert(
                        "Please login before scanning."
                    );

                    return;

                }


                /* --------------------------------
                   DISABLE BUTTON
                -------------------------------- */

                analyzeButton.disabled =
                    true;

                analyzeButton.textContent =
                    "Analyzing...";


                try {

                    let endpoint = "";

                    let payload = {};


                    /* =================================
                       URL
                    ================================= */

                    if (
                        scanType.value === "url"
                    ) {

                        endpoint =
                            "/scan";

                        payload = {

                            url: input

                        };

                    }


                    /* =================================
                       MESSAGE
                    ================================= */

                    else if (
                        scanType.value === "message"
                    ) {

                        endpoint =
                            "/scan-message";

                        payload = {

                            message: input

                        };

                    }


                    /* =================================
                       EMAIL
                    ================================= */

                    else if (
                        scanType.value === "email"
                    ) {

                        endpoint =
                            "/scan-email";

                        payload = {

                            email: input

                        };

                    }


                    /* =================================
                       INVALID SCAN TYPE
                    ================================= */

                    else {

                        throw new Error(
                            "Invalid scan type."
                        );

                    }


                    /* =================================
                       SEND REQUEST
                    ================================= */

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


                    /* =================================
                       READ RESPONSE
                    ================================= */

                    const result =
                        await response.json();


                    /* =================================
                       SERVER ERROR
                    ================================= */

                    if (!response.ok) {

                        throw new Error(
                            result.error ||
                            "Scan failed."
                        );

                    }


                    /* =================================
                       DISPLAY RESULT
                    ================================= */

                    openScanResult(
                        result
                    );

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

                    /*
                     * Always restore the button.
                     * This prevents the scanner from
                     * getting stuck in "Analyzing..."
                     */

                    analyzeButton.disabled =
                        false;

                    analyzeButton.textContent =
                        "Analyze Now";

                }

            }
        );

    }

});