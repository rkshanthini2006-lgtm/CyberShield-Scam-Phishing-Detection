/* ==========================================
   CYBERSHIELD - SCAN HISTORY
   Loads and displays logged-in user's scans
========================================== */

document.addEventListener("DOMContentLoaded", () => {

    /* ==========================================
       ELEMENTS
    ========================================== */

    const historySearch =
        document.getElementById("historySearch");

    const historyFilter =
        document.getElementById("historyFilter");

    const riskFilter =
        document.getElementById("riskFilter");

    const refreshHistory =
        document.getElementById("refreshHistory");

    const retryHistory =
        document.getElementById("retryHistory");

    const historyLoading =
        document.getElementById("historyLoading");

    const historyError =
        document.getElementById("historyError");

    const historyErrorMessage =
        document.getElementById("historyErrorMessage");

    const historyEmpty =
        document.getElementById("historyEmpty");

    const historyTableWrapper =
        document.getElementById("historyTableWrapper");

    const historyTableBody =
        document.getElementById("historyTableBody");

    const historyTotal =
        document.getElementById("historyTotal");

    const historySafe =
        document.getElementById("historySafe");

    const historySuspicious =
        document.getElementById("historySuspicious");

    const historyDangerous =
        document.getElementById("historyDangerous");

    const historyCount =
        document.getElementById("historyCount");


    /* ==========================================
       USER CHECK
    ========================================== */

    const userId =
        localStorage.getItem("user_id");


    if (!userId) {

        showError(
            "No logged-in user was found. Please login again."
        );

        return;

    }


    /* ==========================================
       STORE HISTORY
    ========================================== */

    let scanHistory = [];


    /* ==========================================
       LOAD HISTORY
    ========================================== */

    async function loadHistory() {

        showLoading();

        try {

            const response =
                await fetch(
                    "/scan-history",
                    {
                        method: "GET",

                        headers: {
                            "X-User-ID":
                                userId
                        }
                    }
                );


            const responseText =
                await response.text();


            console.log(
                "History HTTP Status:",
                response.status
            );

            console.log(
                "History Server Response:",
                responseText
            );


            let result;

            try {

                result =
                    JSON.parse(responseText);

            }

            catch (error) {

                throw new Error(
                    "Server returned an invalid response."
                );

            }


            if (!response.ok) {

                throw new Error(
                    result.error ||
                    "Unable to load scan history."
                );

            }


            scanHistory =
                Array.isArray(result.history)
                    ? result.history
                    : [];


            updateSummary(
                scanHistory
            );

            renderHistory();


        }

        catch (error) {

            console.error(
                "CyberShield history error:",
                error
            );

            showError(
                error.message ||
                "Unable to load scan history."
            );

        }

    }


    /* ==========================================
       UPDATE SUMMARY
    ========================================== */

    function updateSummary(records) {

        let safe = 0;

        let suspicious = 0;

        let dangerous = 0;


        records.forEach(
            (record) => {

                const score =
                    Number(
                        record.risk_score
                    );


                if (score >= 90) {

                    safe++;

                }

                else if (score >= 60) {

                    suspicious++;

                }

                else {

                    dangerous++;

                }

            }
        );


        historyTotal.textContent =
            records.length;

        historySafe.textContent =
            safe;

        historySuspicious.textContent =
            suspicious;

        historyDangerous.textContent =
            dangerous;

    }


    /* ==========================================
       RENDER HISTORY
    ========================================== */

    function renderHistory() {

        const searchText =
            historySearch.value
                .trim()
                .toLowerCase();


        const selectedType =
            historyFilter.value;


        const selectedRisk =
            riskFilter.value;


        const filteredRecords =
            scanHistory.filter(
                (record) => {

                    const input =
                        String(
                            record.scan_input || ""
                        ).toLowerCase();


                    const type =
                        String(
                            record.scan_type || ""
                        );


                    const score =
                        Number(
                            record.risk_score
                        );


                    /* SEARCH */

                    const matchesSearch =
                        !searchText ||
                        input.includes(
                            searchText
                        );


                    /* TYPE */

                    const matchesType =
                        selectedType === "all" ||
                        type === selectedType;


                    /* RISK */

                    let matchesRisk = true;


                    if (
                        selectedRisk === "safe"
                    ) {

                        matchesRisk =
                            score >= 90;

                    }

                    else if (
                        selectedRisk === "suspicious"
                    ) {

                        matchesRisk =
                            score >= 60 &&
                            score < 90;

                    }

                    else if (
                        selectedRisk === "dangerous"
                    ) {

                        matchesRisk =
                            score < 60;

                    }


                    return (
                        matchesSearch &&
                        matchesType &&
                        matchesRisk
                    );

                }
            );


        historyCount.textContent =
            `${filteredRecords.length} record${filteredRecords.length === 1 ? "" : "s"}`;


        if (
            filteredRecords.length === 0
        ) {

            historyTableWrapper.style.display =
                "none";

            historyEmpty.style.display =
                "block";

            historyLoading.style.display =
                "none";

            historyError.style.display =
                "none";

            return;

        }


        historyEmpty.style.display =
            "none";

        historyError.style.display =
            "none";

        historyLoading.style.display =
            "none";

        historyTableWrapper.style.display =
            "block";


        historyTableBody.innerHTML = "";


        filteredRecords.forEach(
            (record, index) => {

                const row =
                    document.createElement("tr");


                const score =
                    Number(
                        record.risk_score
                    );


                const risk =
                    getRiskStatus(score);


                const formattedDate =
                    formatDate(
                        record.created_at
                    );


                row.innerHTML = `

                    <td>
                        ${index + 1}
                    </td>

                    <td>

                        <span class="history-type-badge">

                            ${escapeHTML(
                                record.scan_type || "Unknown"
                            )}

                        </span>

                    </td>

                    <td>

                        <div class="history-input">

                            ${escapeHTML(
                                record.scan_input || "-"
                            )}

                        </div>

                    </td>

                    <td>

                        <strong
                            class="history-score ${risk.className}"
                        >

                            ${score}

                        </strong>

                    </td>

                    <td>

                        <span
                            class="history-risk-badge ${risk.className}"
                        >

                            ${risk.label}

                        </span>

                    </td>

                    <td>

                        ${formattedDate}

                    </td>

                `;


                historyTableBody.appendChild(
                    row
                );

            }
        );

    }


    /* ==========================================
       RISK STATUS
    ========================================== */

    function getRiskStatus(score) {

        if (score >= 90) {

            return {

                label:
                    "Safe",

                className:
                    "safe"

            };

        }


        if (score >= 60) {

            return {

                label:
                    "Suspicious",

                className:
                    "suspicious"

            };

        }


        return {

            label:
                "Dangerous",

            className:
                "dangerous"

        };

    }


    /* ==========================================
       DATE FORMAT
    ========================================== */

    function formatDate(dateValue) {

        if (!dateValue) {

            return "-";

        }


        const date =
            new Date(dateValue);

        return date.toLocaleString(
            "en-IN",
            {
                day: "2-digit",
                month: "short",
                year: "numeric",
                hour: "2-digit",
                minute: "2-digit"
            }
        );

    }


    /* ==========================================
       HTML ESCAPE
       Prevents unsafe content in table
    ========================================== */

    function escapeHTML(value) {

        return String(value)
            .replace(
                /&/g,
                "&amp;"
            )
            .replace(
                /</g,
                "&lt;"
            )
            .replace(
                />/g,
                "&gt;"
            )
            .replace(
                /"/g,
                "&quot;"
            )
            .replace(
                /'/g,
                "&#039;"
            );

    }


    /* ==========================================
       LOADING
    ========================================== */

    function showLoading() {

        historyLoading.style.display =
            "block";

        historyError.style.display =
            "none";

        historyEmpty.style.display =
            "none";

        historyTableWrapper.style.display =
            "none";

    }


    /* ==========================================
       ERROR
    ========================================== */

    function showError(message) {

        historyLoading.style.display =
            "none";

        historyEmpty.style.display =
            "none";

        historyTableWrapper.style.display =
            "none";

        historyError.style.display =
            "block";


        if (historyErrorMessage) {

            historyErrorMessage.textContent =
                message;

        }

    }


    /* ==========================================
       SEARCH
    ========================================== */

    if (historySearch) {

        historySearch.addEventListener(
            )
        ) {

            return String(
                dateValue
            );

        }


        return date.toLocaleString(
            "en-IN",
            {
                day:
                    "2-digit",

                month:
                    "short",

                year:
                    "numeric",

                hour:
                    "2-digit",

                minute:
                    "2-digit"

            }
        );

    }


    /* ==========================================
       HTML ESCAPE
       Prevents unsafe content in table
    ========================================== */

    function escapeHTML(value) {

        return String(value)
            .replace(
                /&/g,
                "&amp;"
            )
            .replace(
                /</g,
                "&lt;"
            )
            .replace(
                />/g,
                "&gt;"
            )
            .replace(
                /"/g,
                "&quot;"
            )
            .replace(
                /'/g,
                "&#039;"
            );

    }


    /* ==========================================
       LOADING
    ========================================== */

    function showLoading() {

        historyLoading.style.display =
            "block";

        historyError.style.display =
            "none";

        historyEmpty.style.display =
            "none";

        historyTableWrapper.style.display =
            "none";

    }


    /* ==========================================
       ERROR
    ========================================== */

    function showError(message) {

        historyLoading.style.display =
            "none";

        historyEmpty.style.display =
            "none";

        historyTableWrapper.style.display =
            "none";

        historyError.style.display =
            "block";


        if (historyErrorMessage) {

            historyErrorMessage.textContent =
                message;

        }

    }


    /* ==========================================
       SEARCH
    ========================================== */

    if (historySearch) {

        historySearch.addEventListener(
            "input",
            renderHistory
        );

    }


    /* ==========================================
       TYPE FILTER
    ========================================== */

    if (historyFilter) {

        historyFilter.addEventListener(
            "change",
            renderHistory
        );

    }


    /* ==========================================
       RISK FILTER
    ========================================== */

    if (riskFilter) {

        riskFilter.addEventListener(
            "change",
            renderHistory
        );

    }


    /* ==========================================
       REFRESH
    ========================================== */

    if (refreshHistory) {

        refreshHistory.addEventListener(
            "click",
            loadHistory
        );

    }


    /* ==========================================
       RETRY
    ========================================== */

    if (retryHistory) {

        retryHistory.addEventListener(
            "click",
            loadHistory
        );

    }


    /* ==========================================
       INITIAL LOAD
    ========================================== */

    loadHistory();

});