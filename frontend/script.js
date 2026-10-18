const API_BASE = "http://127.0.0.1:5000";

const loginScreen = document.getElementById("loginScreen");
const appShell = document.getElementById("appShell");
const loginForm = document.getElementById("loginForm");
const loginResult = document.getElementById("loginResult");

const fileInput = document.getElementById("fileInput");
const fileName = document.getElementById("fileName");
const hashOutput = document.getElementById("hashOutput");
const analysisResult = document.getElementById("analysisResult");

let selectedFile = null;
let currentHash = null;
let monitoredFiles = [];
let evidenceRecords = [];
let auditLogs = [];

function showResult(message, type = "") {
    analysisResult.textContent = message;
    analysisResult.className = "result" + (type ? " " + type : "");
}

function showLoginResult(message, type = "") {
    loginResult.textContent = message;
    loginResult.className = "result" + (type ? " " + type : "");
}

function shortHash(hash) {
    return hash ? hash.slice(0, 18) + "..." : "Unavailable";
}

function formatTime(value) {
    if (!value) return "—";

    // SQLite timestamps are interpreted as local display values here.
    const parsed = new Date(value.replace(" ", "T"));
    if (Number.isNaN(parsed.getTime())) return value;

    return parsed.toLocaleString();
}

async function api(path, options = {}) {
    const response = await fetch(API_BASE + path, options);

    let data = {};
    try {
        data = await response.json();
    } catch {
        data = { message: "Backend returned an invalid response." };
    }

    if (!response.ok) {
        throw new Error(data.message || `Request failed (${response.status})`);
    }

    return data;
}


/* ============================================================
   LOGIN
   ============================================================ */

loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    const username = document.getElementById("username").value.trim();
    const password = document.getElementById("password").value;

    if (!username || !password) {
        showLoginResult("Enter username and password.", "warning");
        return;
    }

    const submitButton = loginForm.querySelector("button[type='submit']");
    submitButton.disabled = true;
    submitButton.textContent = "Connecting...";

    try {
        const data = await api("/api/login", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                username,
                password
            })
        });

        sessionStorage.setItem("cybertrace_user", JSON.stringify(data.user));

        loginForm.reset();
        showLoginResult("Login successful.", "success");
        enterApplication(data.user);

    } catch (error) {
        showLoginResult(error.message, "danger");
    } finally {
        submitButton.disabled = false;
        submitButton.textContent = "Login";
    }
});


function enterApplication(user) {
    loginScreen.classList.add("hidden");
    appShell.classList.remove("hidden");

    document.getElementById("loggedUser").textContent = user.username;
    document.getElementById("loggedRole").textContent = user.role;

    loadAllData();
}


function logout() {
    sessionStorage.removeItem("cybertrace_user");
    appShell.classList.add("hidden");
    loginScreen.classList.remove("hidden");

    showLoginResult("You have been logged out.");
}


/* ============================================================
   LOAD BACKEND DATA
   ============================================================ */

async function loadDashboard() {
    const data = await api("/api/dashboard");

    document.getElementById("totalFiles").textContent = data.total_files ?? 0;
    document.getElementById("verifiedFiles").textContent = data.safe_files ?? 0;
    document.getElementById("alertFiles").textContent = data.modified_files ?? 0;
    document.getElementById("totalRecords").textContent = data.evidence_records ?? 0;
}


async function loadFiles() {
    monitoredFiles = await api("/api/files");
    renderFiles();
}


async function loadEvidence() {
    evidenceRecords = await api("/api/evidence");
    auditLogs = await api("/api/logs");
    renderEvidence();
}


async function loadAllData() {
    try {
        await Promise.all([
            loadDashboard(),
            loadFiles(),
            loadEvidence()
        ]);
    } catch (error) {
        showResult("Could not load backend data: " + error.message, "danger");
    }
}


/* ============================================================
   FILE SELECTION
   ============================================================ */

fileInput.addEventListener("change", () => {
    selectedFile = fileInput.files[0] || null;
    currentHash = null;

    fileName.textContent = selectedFile
        ? `${selectedFile.name} (${selectedFile.size} bytes)`
        : "Choose a file from your device";

    hashOutput.textContent = "Hash will be calculated by Flask.";
    showResult(
        selectedFile
            ? "File selected. Register it or verify it against an existing baseline."
            : "No file selected."
    );
});


/* ============================================================
   REGISTER BASELINE
   ============================================================ */

document.getElementById("registerBtn").addEventListener("click", async () => {
    if (!selectedFile) {
        showResult("Please select a file first.", "warning");
        return;
    }

    const button = document.getElementById("registerBtn");
    button.disabled = true;
    button.textContent = "Registering...";

    try {
        showResult("Uploading file and calculating SHA-256 on the Flask server...");

        const formData = new FormData();
        formData.append("file", selectedFile);

        const data = await api("/api/files/upload", {
            method: "POST",
            body: formData
        });

        currentHash = data.file.sha256;
        hashOutput.textContent = currentHash;

        showResult(
            `Baseline registered successfully. File ID: ${data.file.id}`,
            "success"
        );

        await loadAllData();

    } catch (error) {
        showResult(error.message, "warning");
    } finally {
        button.disabled = false;
        button.textContent = "Register Baseline";
    }
});


/* ============================================================
   VERIFY INTEGRITY
   ============================================================ */

document.getElementById("verifyBtn").addEventListener("click", async () => {
    if (!selectedFile) {
        showResult("Please select a file first.", "warning");
        return;
    }

    // Find the backend baseline by filename.
    const baseline = monitoredFiles.find(
        item => item.file_name === selectedFile.name
    );

    if (!baseline) {
        showResult(
            "No backend baseline exists for this filename. Register the original file first.",
            "warning"
        );
        return;
    }

    const button = document.getElementById("verifyBtn");
    button.disabled = true;
    button.textContent = "Verifying...";

    try {
        showResult("Uploading current copy and comparing SHA-256 with the backend baseline...");

        const formData = new FormData();
        formData.append("file", selectedFile);

        const data = await api(
            `/api/files/${baseline.id}/verify-upload`,
            {
                method: "POST",
                body: formData
            }
        );

        currentHash = data.current_hash;
        hashOutput.textContent = currentHash || "Unavailable";

        if (data.status === "SAFE") {
            showResult(
                "INTEGRITY VERIFIED: the file matches its registered baseline.",
                "success"
            );
        } else if (data.status === "MODIFIED") {
            showResult(
                "INTEGRITY ALERT: the file differs from its registered baseline.",
                "danger"
            );
        } else {
            showResult(data.message || "Verification completed.", "warning");
        }

        await loadAllData();

    } catch (error) {
        showResult(error.message, "danger");
    } finally {
        button.disabled = false;
        button.textContent = "Verify Integrity";
    }
});


/* ============================================================
   COPY HASH
   ============================================================ */

document.getElementById("copyHash").addEventListener("click", async () => {
    if (!currentHash) {
        showResult("There is no calculated hash to copy.", "warning");
        return;
    }

    try {
        await navigator.clipboard.writeText(currentHash);
        showResult("SHA-256 hash copied.", "success");
    } catch {
        showResult(
            "Clipboard access is unavailable. Select and copy the hash manually.",
            "warning"
        );
    }
});


/* ============================================================
   RENDER MONITORED FILES
   ============================================================ */

function renderFiles() {
    const table = document.getElementById("filesTable");
    table.replaceChildren();

    if (!monitoredFiles.length) {
        const row = table.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 5;
        cell.className = "empty";
        cell.textContent = "No monitored files yet.";
        return;
    }

    monitoredFiles.forEach(file => {
        const row = table.insertRow();

        const values = [
            file.id,
            file.file_name,
            file.status,
            shortHash(file.original_hash),
            shortHash(file.current_hash)
        ];

        values.forEach((value, index) => {
            const cell = row.insertCell();
            cell.textContent = value;

            if (index === 2) {
                if (file.status === "SAFE") cell.className = "status-safe";
                if (file.status === "MODIFIED") cell.className = "status-modified";
                if (file.status === "DELETED") cell.className = "status-deleted";
            }

            if (index === 3 || index === 4) {
                const code = document.createElement("code");
                code.textContent = value;
                cell.replaceChildren(code);
            }
        });
    });
}


/* ============================================================
   RENDER EVIDENCE + AUDIT LOGS
   ============================================================ */

function renderEvidence() {
    const table = document.getElementById("evidenceTable");
    table.replaceChildren();

    const fileMap = new Map(
        monitoredFiles.map(file => [file.file_name, file])
    );

    const rows = [];

    // Digital evidence: modifications/deletions with old/new hashes.
    evidenceRecords.forEach(record => {
        rows.push({
            time: record.detected_at,
            file: record.file_name,
            hash: record.new_hash || record.old_hash,
            event: record.event_type,
            result: record.status
        });
    });

    // Audit records: registrations and successful integrity checks.
    auditLogs.forEach(log => {
        let fileNameFromLog = "—";
        const separatorIndex = (log.details || "").indexOf(": ");

        if (separatorIndex >= 0) {
            fileNameFromLog = log.details.slice(separatorIndex + 2);
        }

        const file = fileMap.get(fileNameFromLog);

        let event = log.action;
        let result = log.action;

        if (log.action === "FILE_ADDED") {
            event = "BASELINE REGISTERED";
            result = "REGISTERED";
        } else if (log.action === "INTEGRITY_CHECK") {
            event = "INTEGRITY CHECK";
            result = "VERIFIED";
        } else if (log.action === "INTEGRITY_VIOLATION") {
            event = "INTEGRITY CHECK";
            result = "MISMATCH";
        } else if (log.action === "FILE_DELETED") {
            event = "FILE CHECK";
            result = "DELETED";
        }

        rows.push({
            time: log.timestamp,
            file: fileNameFromLog,
            hash: file ? file.current_hash : null,
            event,
            result
        });
    });

    rows.sort((a, b) =>
        String(b.time || "").localeCompare(String(a.time || ""))
    );

    if (!rows.length) {
        const row = table.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 5;
        cell.className = "empty";
        cell.textContent = "No evidence records yet.";
        return;
    }

    rows.forEach(record => {
        const row = table.insertRow();

        [
            formatTime(record.time),
            record.file,
            shortHash(record.hash),
            record.event,
            record.result
        ].forEach((value, index) => {
            const cell = row.insertCell();
            cell.textContent = value;

            if (index === 2) {
                const code = document.createElement("code");
                code.textContent = value;
                cell.replaceChildren(code);
            }
        });
    });
}


/* ============================================================
   EXPORT BACKEND DATA
   ============================================================ */

document.getElementById("exportBtn").addEventListener("click", () => {
    const report = {
        project: "CyberTrace",
        exportedAt: new Date().toISOString(),
        source: "Flask + SQLite backend",
        monitoredFiles,
        evidenceRecords,
        auditLogs
    };

    const blob = new Blob(
        [JSON.stringify(report, null, 2)],
        { type: "application/json" }
    );

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "cybertrace-evidence-report.json";
    link.click();

    URL.revokeObjectURL(url);
});


/* ============================================================
   REFRESH + LOGOUT
   ============================================================ */

document.getElementById("refreshBtn").addEventListener("click", async () => {
    showResult("Refreshing data from Flask backend...");
    await loadAllData();
    showResult("Dashboard refreshed from the backend.", "success");
});

document.getElementById("logoutBtn").addEventListener("click", logout);


/* ============================================================
   STARTUP
   ============================================================ */

const savedUser = sessionStorage.getItem("cybertrace_user");

if (savedUser) {
    try {
        enterApplication(JSON.parse(savedUser));
    } catch {
        sessionStorage.removeItem("cybertrace_user");
    }
}
