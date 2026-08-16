/* ==========================================
   CYBERSHIELD - DASHBOARD
   Dashboard Data, Statistics & Quick Scan
========================================== */


document.addEventListener("DOMContentLoaded", () => {

    loadDashboardStats();

    setupQuickScan();

});


/* ==========================================
   LOAD DASHBOARD STATISTICS
========================================== */

async function loadDashboardStats() {

    try {

        const response = await fetch(
            "/dashboard-stats"
        );


        if (!response.ok) {

            throw new Error(
                `Dashboard API error: ${response.status}`
            );

        }


        const data = await response.json();


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
            document.getElementById("totalScans");

        if (totalScans) {

            totalScans.textContent =
                data.total_scans;

        }


        /* ======================================
           THREATS DETECTED
        ====================================== */

        const threatsDetected =
            document.getElementById("threatsDetected");

        if (threatsDetected) {

            threatsDetected.textContent =
                data.threats_detected;

        }


        /* ======================================
           SAFE SCANS
        ====================================== */

        const safeScans =
            document.getElementById("safeScans");

        if (safeScans) {

            safeScans.textContent =
                data.safe_scans;

        }


        /* ======================================
           TOTAL REPORTS
        ====================================== */

        const totalReports =
            document.getElementById("totalReports");

        if (totalReports) {

            totalReports.textContent =
                data.total_reports;

        }


        /* ======================================
           SUSPICIOUS SCANS
        ====================================== */

        const suspiciousScans =
            document.getElementById(
                "suspiciousScans"
            );

        if (suspiciousScans) {

            suspiciousScans.textContent =
                data.suspicious_scans;

        }


        /* ======================================
           DANGEROUS SCANS
        ====================================== */

        const dangerousScans =
            document.getElementById(
                "dangerousScans"
            );

        if (dangerousScans) {

            dangerousScans.textContent =
                data.dangerous_scans;

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


    if (!quickScanInput || !quickScanButton) {

        console.warn(
            "Quick Scan elements not found."
        );

        return;

    }


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
               GET LOGGED-IN USER ID
            ====================================== */

            const userId =
                localStorage.getItem("user_id");


            if (!userId) {

                alert(
                    "Please login before scanning."
                );

                return;

            }


            /* ======================================
               DISABLE BUTTON
            ====================================== */

            quickScanButton.disabled = true;


            const originalText =
                quickScanButton.innerHTML;


            quickScanButton.innerHTML =
                '<i class="fa-solid fa-spinner fa-spin"></i> Scanning...';


            try {

                /* ======================================
                   SEND URL TO FLASK
                ====================================== */

                const response =
                    await fetch(
                        "/scan",
                        {
                            method: "POST",

                            headers: {

                                "Content-Type":
                                    "application/json",

                                "X-User-ID":
                                    userId

                            },

                            body:
                                JSON.stringify({
                                    url: url
                                })
                        }
                    );


                const result =
                    await response.json();


                console.log(
                    "Quick Scan Result:",
                    result
                );


                /* ======================================
                   HANDLE ERROR
                ====================================== */

                if (!response.ok) {

                    throw new Error(
                        result.error ||
                        "Scan failed."
                    );

                }


                /* ======================================
                   DISPLAY RESULT
                ====================================== */

                const risk =
                    result.risk ||
                    "Unknown";

                const score =
                    result.score ?? 0;


                let message =
                    `Risk: ${risk}\nScore: ${score}/100`;


                if (
                    result.reasons &&
                    result.reasons.length > 0
                ) {

                    message +=
                        "\n\nReasons:\n- " +
                        result.reasons.join(
                            "\n- "
                        );

                }

                else {

                    message +=
                        "\n\nNo suspicious indicators found.";

                }


                alert(message);


                /* ======================================
                   REFRESH DASHBOARD STATISTICS
                ====================================== */

                loadDashboardStats();


                /* ======================================
                   CLEAR INPUT
                ====================================== */

                quickScanInput.value = "";

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

            }

            finally {

                quickScanButton.disabled =
                    false;

                quickScanButton.innerHTML =
                    originalText;

            }

        }
    );

}