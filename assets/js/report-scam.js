/* ==========================================
   CYBERSHIELD - REPORT SCAM
   Handles scam report form submission
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    const scamType =
        document.getElementById("scamType");

    const scamUrl =
        document.getElementById("scamUrl");

    const scamDescription =
        document.getElementById("scamDescription");

    const reporterEmail =
        document.getElementById("reporterEmail");

    const submitScamReport =
        document.getElementById("submitScamReport");

    const reportStatus =
        document.getElementById("reportStatus");


    /* ==========================================
       SUBMIT SCAM REPORT
    ========================================== */

    if (submitScamReport) {

        submitScamReport.addEventListener(
            "click",
            async () => {

                const type =
                    scamType.value.trim();

                const url =
                    scamUrl.value.trim();

                const description =
                    scamDescription.value.trim();

                const email =
                    reporterEmail.value.trim();


                /* ==========================================
                   BASIC VALIDATION
                ========================================== */

                if (!type) {

                    alert(
                        "Please select a scam type."
                    );

                    return;

                }


                if (!description) {

                    alert(
                        "Please describe the scam."
                    );

                    return;

                }


                /* ==========================================
                   DISABLE BUTTON
                ========================================== */

                submitScamReport.disabled = true;

                const originalText =
                    submitScamReport.innerHTML;

                submitScamReport.innerHTML =
                    '<i class="fa-solid fa-spinner fa-spin"></i> Submitting...';


                try {

                    /* ==========================================
                       SEND REPORT TO BACKEND
                    ========================================== */

                    const response =
                        await fetch(
                            "/report-scam",
                            {
                                method: "POST",

                                headers: {
                                    "Content-Type":
                                        "application/json"
                                },

                                body:
                                    JSON.stringify({

                                        scam_type: type,

                                        url: url,

                                        description:
                                            description,

                                        email: email

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
                            "Unable to submit scam report."
                        );

                    }


                    /* ==========================================
                       SUCCESS
                    ========================================== */

                    if (reportStatus) {

                        reportStatus.textContent =
                            result.message ||
                            "Scam report submitted successfully.";

                        reportStatus.style.display =
                            "block";

                        reportStatus.style.color =
                            "#00E676";

                    }


                    /* ==========================================
                       CLEAR FORM
                    ========================================== */

                    scamType.value = "";

                    scamUrl.value = "";

                    scamDescription.value = "";

                    reporterEmail.value = "";


                }

                catch (error) {

                    console.error(
                        "CyberShield report error:",
                        error
                    );


                    if (reportStatus) {

                        reportStatus.textContent =
                            error.message ||
                            "Unable to submit the report.";

                        reportStatus.style.display =
                            "block";

                        reportStatus.style.color =
                            "#FF4D4D";

                    }

                }

                finally {

                    submitScamReport.disabled =
                        false;

                    submitScamReport.innerHTML =
                        originalText;

                }

            }
        );

    }

});