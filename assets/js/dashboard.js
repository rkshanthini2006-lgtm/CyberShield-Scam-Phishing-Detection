/* ==========================================
   CYBERSHIELD - DASHBOARD
   Dashboard Data, Statistics & Quick Scan
========================================== */


document.addEventListener(
    "DOMContentLoaded",
    () => {

        loadDashboardStats();

        setupQuickScan();

    }
);


/* ==========================================
   LOAD DASHBOARD STATISTICS
========================================== */

async function loadDashboardStats() {

    try {

        const userId =
            localStorage.getItem(
                "user_id"
            );


        if (!userId) {

            console.error(
                "CyberShield Dashboard: User ID not found."
            );

            return;

        }


        const response =
            await fetch(
                "/dashboard-stats",
                {
                    method: "GET",

                    headers: {

                        "X-User-ID":
                            userId

                    }

                }
            );


        if (!response.ok) {

            throw new Error(
                `Dashboard API error: ${response.status}`
            );

        }


        const data =
            await response.json();


        console.log(
            "CyberShield Dashboard Data:",
            data
        );


        if (!data.success) {

            throw new Error(
                data.error ||
                "Unable to load dashboard data."
            );

        }


        /* ======================================
           TOTAL SCANS
        ====================================== */

        const totalScans =
            document.getElementById(
                "totalScans"
            );


        if (totalScans) {

            totalScans.textContent =
                data.total_scans ?? 0;

        }


        /* ======================================
           THREATS DETECTED
        ====================================== */

        const threatsDetected =
            document.getElementById(
                "threatsDetected"
            );


        if (threatsDetected) {

            threatsDetected.textContent =
                data.threats_detected ?? 0;

        }


        /* ======================================
           SAFE SCANS
        ====================================== */

        const safeScans =
            document.getElementById(
                "safeScans"
            );


        if (safeScans) {

            safeScans.textContent =
                data.safe_scans ?? 0;

        }


        /* ======================================
           TOTAL REPORTS
        ====================================== */

        const totalReports =
            document.getElementById(
                "totalReports"
            );


        if (totalReports) {

            totalReports.textContent =
                data.total_reports ?? 0;

        }

    }


    catch (error) {

        console.error(
            "CyberShield Dashboard Error:",
            error
        );

    }

}


/* ==========================================
   QUICK SECURITY SCAN
========================================== */

function setupQuickScan() {


    const quickScanInput =
        document.getElementById(
            "quickScanInput"
        );


    const quickScanButton =
        document.getElementById(
            "quickScanButton"
        );


    const quickScanResultOverlay =
        document.getElementById(
            "quickScanResultOverlay"
        );


    const quickScanResult =
        document.getElementById(
            "quickScanResult"
        );


    const closeQuickScanResult =
        document.getElementById(
            "closeQuickScanResult"
        );


    const quickResultRisk =
        document.getElementById(
            "quickResultRisk"
        );


    const quickResultScore =
        document.getElementById(
            "quickResultScore"
        );


    const quickResultReasons =
        document.getElementById(
            "quickResultReasons"
        );


    if (
        !quickScanInput ||
        !quickScanButton
    ) {

        console.warn(
            "Quick Scan elements not found."
        );

        return;

    }


    /* ==========================================
       OPEN RESULT MODAL
    ========================================== */

    function openQuickScanResult(result) {


        if (
            !quickScanResult ||
            !quickScanResultOverlay
        ) {

            return;

        }


        /* --------------------------------------
           RISK
        -------------------------------------- */

        if (quickResultRisk) {

            quickResultRisk.textContent =
                result.risk ||
                "Unknown";

        }


        /* --------------------------------------
           SCORE
        -------------------------------------- */

        if (quickResultScore) {

            quickResultScore.textContent =
                `${result.score ?? 0}/100`;

        }


        /* --------------------------------------
           REASONS
        -------------------------------------- */

        if (quickResultReasons) {

            quickResultReasons.innerHTML =
                "";


            const reasons =
                Array.isArray(
                    result.reasons
                )
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


                        quickResultReasons.appendChild(
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


                quickResultReasons.appendChild(
                    li
                );

            }

        }


        /* --------------------------------------
           REMOVE OLD RISK CLASSES
        -------------------------------------- */

        quickScanResult.classList.remove(
            "safe",
            "suspicious",
            "dangerous"
        );


        /* --------------------------------------
           APPLY RISK CLASS
        -------------------------------------- */

        const risk =
            String(
                result.risk || ""
            ).toLowerCase();


        if (risk === "safe") {

            quickScanResult.classList.add(
                "safe"
            );

        }

        else if (
            risk === "suspicious"
        ) {

            quickScanResult.classList.add(
                "suspicious"
            );

        }

        else if (
            risk === "dangerous"
        ) {

            quickScanResult.classList.add(
                "dangerous"
            );

        }


        /* --------------------------------------
           SHOW RESULT MODAL
        -------------------------------------- */

        quickScanResultOverlay.style.display =
            "flex";


        /* --------------------------------------
           PREVENT BACKGROUND SCROLL
        -------------------------------------- */

        document.body.style.overflow =
            "hidden";


        /* --------------------------------------
           RESTORE BUTTON
        -------------------------------------- */

        quickScanButton.disabled =
            false;


        quickScanButton.innerHTML =
            '<i class="fa-solid fa-magnifying-glass"></i> Scan URL';

    }


    /* ==========================================
       RESET / CLOSE QUICK SCAN RESULT
    ========================================== */

    function resetQuickScan() {


        /* --------------------------------------
           HIDE RESULT MODAL
        -------------------------------------- */

        if (quickScanResultOverlay) {

            quickScanResultOverlay.style.display =
                "none";

        }


        /* --------------------------------------
           RESTORE PAGE SCROLL
        -------------------------------------- */

        document.body.style.overflow =
            "";



        /* --------------------------------------
           CLEAR INPUT
        -------------------------------------- */

        quickScanInput.value =
            "";


        /* --------------------------------------
           CLEAR RISK
        -------------------------------------- */

        if (quickResultRisk) {

            quickResultRisk.textContent =
                "-";

        }


        /* --------------------------------------
           CLEAR SCORE
        -------------------------------------- */

        if (quickResultScore) {

            quickResultScore.textContent =
                "-";

        }


        /* --------------------------------------
           CLEAR REASONS
        -------------------------------------- */

        if (quickResultReasons) {

            quickResultReasons.innerHTML =
                "";

        }


        /* --------------------------------------
           REMOVE RISK CLASSES
        -------------------------------------- */

        if (quickScanResult) {

            quickScanResult.classList.remove(
                "safe",
                "suspicious",
                "dangerous"
            );

        }


        /* --------------------------------------
           RESTORE BUTTON
        -------------------------------------- */

        quickScanButton.disabled =
            false;


        quickScanButton.innerHTML =
            '<i class="fa-solid fa-magnifying-glass"></i> Scan URL';

    }


    /* ==========================================
       CLOSE BUTTON
    ========================================== */

    if (closeQuickScanResult) {

        closeQuickScanResult.addEventListener(
            "click",
            function (event) {

                event.preventDefault();

                event.stopPropagation();

                resetQuickScan();

            }
        );

    }


    /* ==========================================
       CLICK OUTSIDE MODAL
    ========================================== */

    if (quickScanResultOverlay) {

        quickScanResultOverlay.addEventListener(
            "click",
            function (event) {

                if (
                    event.target ===
                    quickScanResultOverlay
                ) {

                    resetQuickScan();

                }

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
                quickScanResultOverlay &&
                quickScanResultOverlay.style.display !== "none"
            ) {

                resetQuickScan();

            }

        }
    );


    /* ==========================================
       SCAN URL
    ========================================== */

    quickScanButton.addEventListener(
        "click",
        async () => {


            const url =
                quickScanInput.value.trim();


            /* ======================================
               VALIDATION
            ====================================== */

            if (!url) {

                alert(
                    "Please enter a URL to scan."
                );

                return;

            }


            /* ======================================
               USER CHECK
            ====================================== */

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


            /* ======================================
               CLOSE OLD RESULT BEFORE NEW SCAN
            ====================================== */

            if (quickScanResultOverlay) {

                quickScanResultOverlay.style.display =
                    "none";

            }


            if (quickScanResult) {

                quickScanResult.classList.remove(
                    "safe",
                    "suspicious",
                    "dangerous"
                );

            }


            /* Restore page scroll */

            document.body.style.overflow =
                "";


            /* ======================================
               LOADING STATE
            ====================================== */

            quickScanButton.disabled =
                true;


            quickScanButton.innerHTML =
                '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';


            try {


                /* ======================================
                   SEND REQUEST TO SAME ENDPOINT
                   USED BY scan.html
                ====================================== */

                const response =
                    await fetch(
                        "/scan",
                        {

                            method:
                                "POST",

                            headers:
                                {

                                    "Content-Type":
                                        "application/json",

                                    "X-User-ID":
                                        userId

                                },

                            body:
                                JSON.stringify(
                                    {
                                        url:
                                            url
                                    }
                                )

                        }
                    );


                /* ======================================
                   READ RESPONSE
                ====================================== */

                const result =
                    await response.json();


                console.log(
                    "CyberShield Quick Scan Result:",
                    result
                );


                /* ======================================
                   HANDLE SERVER ERROR
                ====================================== */

                if (!response.ok) {

                    throw new Error(
                        result.error ||
                        "Scan failed."
                    );

                }


                /* ======================================
                   DISPLAY SCANNER-STYLE RESULT
                ====================================== */

                openQuickScanResult(
                    result
                );


                /* ======================================
                   UPDATE DASHBOARD COUNTERS
                ====================================== */

                loadDashboardStats();

            }


            catch (error) {

                console.error(
                    "CyberShield Quick Scan Error:",
                    error
                );


                alert(
                    error.message ||
                    "Unable to complete the scan."
                );


                /* Restore button */

                quickScanButton.disabled =
                    false;


                quickScanButton.innerHTML =
                    '<i class="fa-solid fa-magnifying-glass"></i> Scan URL';

            }

        }
    );

}