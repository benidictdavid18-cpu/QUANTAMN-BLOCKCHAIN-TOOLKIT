// Quantum-Resistant Blockchain Security Toolkit - Frontend JavaScript

const API_BASE_URL = 'https://quantum-toolkit-backend.onrender.com';
let currentScanId = null;

// Initialize
document.addEventListener('DOMContentLoaded', function () {
    loadStatistics();
    setupFileUpload();
    setupFormSubmit();
});

// Load statistics
async function loadStatistics() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/stats`);
        const data = await response.json();

        document.getElementById('totalScans').textContent = data.total_scans || 0;
        document.getElementById('totalVulnerabilities').textContent = data.total_vulnerabilities_detected || 0;

        // Animate numbers
        animateValue('totalScans', 0, data.total_scans || 0, 1000);
        animateValue('totalVulnerabilities', 0, data.total_vulnerabilities_detected || 0, 1000);
    } catch (error) {
        console.error('Failed to load statistics:', error);
    }
}

// Animate counter
function animateValue(id, start, end, duration) {
    const element = document.getElementById(id);
    const range = end - start;
    const increment = range / (duration / 16);
    let current = start;

    const timer = setInterval(() => {
        current += increment;
        if (current >= end) {
            element.textContent = end;
            clearInterval(timer);
        } else {
            element.textContent = Math.floor(current);
        }
    }, 16);
}

// File upload handling
function setupFileUpload() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('codeFile');
    const fileName = document.getElementById('fileName');

    dropZone.addEventListener('click', () => fileInput.click());

    fileInput.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            fileName.textContent = `Selected: ${e.target.files[0].name}`;
        }
    });

    // Drag and drop
    dropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropZone.classList.add('border-purple-500');
    });

    dropZone.addEventListener('dragleave', () => {
        dropZone.classList.remove('border-purple-500');
    });

    dropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropZone.classList.remove('border-purple-500');

        if (e.dataTransfer.files.length > 0) {
            fileInput.files = e.dataTransfer.files;
            fileName.textContent = `Selected: ${e.dataTransfer.files[0].name}`;
        }
    });
}

// Form submission
function setupFormSubmit() {
    const form = document.getElementById('scanForm');

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        await scanCode();
    });
}

// Scan code
async function scanCode() {
    const form = document.getElementById('scanForm');
    const loadingIndicator = document.getElementById('loadingIndicator');
    const submitBtn = document.getElementById('submitBtn');

    // Get form data
    const formData = new FormData();
    formData.append('file', document.getElementById('codeFile').files[0]);
    formData.append('company_name', document.getElementById('companyName').value);
    formData.append('sector', document.getElementById('sector').value);
    formData.append('contact_email', document.getElementById('contactEmail').value);

    try {
        // Show loading
        form.classList.add('hidden');
        loadingIndicator.classList.remove('hidden');
        submitBtn.disabled = true;

        // Make API call
        const response = await fetch(`${API_BASE_URL}/api/scan`, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.success) {
            currentScanId = data.scan_id;
            displayResults(data);
            loadStatistics(); // Refresh stats
        } else {
            alert('Scan failed: ' + (data.error || 'Unknown error'));
        }

    } catch (error) {
        console.error('Scan error:', error);
        alert('Failed to scan code. Please ensure the backend server is running.');
    } finally {
        // Hide loading
        loadingIndicator.classList.add('hidden');
        submitBtn.disabled = false;
    }
}

// Display scan results
function displayResults(data) {
    const resultsSection = document.getElementById('results');
    resultsSection.classList.remove('hidden');

    // Scroll to results
    resultsSection.scrollIntoView({ behavior: 'smooth' });

    // Update risk score
    const riskScore = data.risk_score || 0;
    document.getElementById('riskScoreValue').textContent = Math.round(riskScore);

    const riskLevel = document.getElementById('riskLevel');
    const riskCard = document.getElementById('riskScoreCard');

    if (riskScore < 30) {
        riskLevel.textContent = 'LOW RISK';
        riskLevel.className = 'mt-2 px-4 py-1 rounded-full text-white font-semibold bg-green-500';
        riskCard.className = 'bg-white rounded-xl shadow-lg p-8 border-l-4 border-green-500';
    } else if (riskScore < 70) {
        riskLevel.textContent = 'MEDIUM RISK';
        riskLevel.className = 'mt-2 px-4 py-1 rounded-full text-white font-semibold bg-orange-500';
        riskCard.className = 'bg-white rounded-xl shadow-lg p-8 border-l-4 border-orange-500';
    } else {
        riskLevel.textContent = 'HIGH RISK';
        riskLevel.className = 'mt-2 px-4 py-1 rounded-full text-white font-semibold bg-red-500';
        riskCard.className = 'bg-white rounded-xl shadow-lg p-8 border-l-4 border-red-500';
    }

    // Display vulnerabilities
    displayVulnerabilities(data.scan_results.vulnerabilities || []);

    // Display migration plan
    displayMigrationPlan(data.migration_plan);
}

// Display vulnerabilities table
function displayVulnerabilities(vulnerabilities) {
    const container = document.getElementById('vulnerabilitiesTable');

    if (vulnerabilities.length === 0) {
        container.innerHTML = '<p class="text-green-600 font-semibold">No vulnerabilities detected! Your code appears to be quantum-safe.</p>';
        return;
    }

    let html = '<div class="overflow-x-auto"><table class="w-full">';
    html += '<thead class="bg-gray-100"><tr>';
    html += '<th class="px-4 py-3 text-left">Algorithm</th>';
    html += '<th class="px-4 py-3 text-left">Severity</th>';
    html += '<th class="px-4 py-3 text-left">Line</th>';
    html += '<th class="px-4 py-3 text-left">Description</th>';
    html += '</tr></thead><tbody>';

    vulnerabilities.forEach((vuln, index) => {
        const severityColor = vuln.severity === 'HIGH' ? 'text-red-600' :
            vuln.severity === 'MEDIUM' ? 'text-orange-600' : 'text-yellow-600';

        html += `<tr class="${index % 2 === 0 ? 'bg-gray-50' : 'bg-white'}">`;
        html += `<td class="px-4 py-3 font-semibold">${vuln.algorithm}</td>`;
        html += `<td class="px-4 py-3 ${severityColor} font-semibold">${vuln.severity}</td>`;
        html += `<td class="px-4 py-3">${vuln.line_number}</td>`;
        html += `<td class="px-4 py-3 text-sm">${vuln.description}</td>`;
        html += '</tr>';
    });

    html += '</tbody></table></div>';
    container.innerHTML = html;
}

// Display migration plan
function displayMigrationPlan(migrationPlan) {
    const container = document.getElementById('migrationPlan');

    if (!migrationPlan || !migrationPlan.migration_steps) {
        container.innerHTML = '<p class="text-gray-600">No migration needed.</p>';
        return;
    }

    let html = '<div class="space-y-4">';

    migrationPlan.migration_steps.forEach((step, index) => {
        html += `<div class="border border-gray-200 rounded-lg p-4">`;
        html += `<div class="flex items-start">`;
        html += `<div class="flex-shrink-0 bg-purple-600 text-white rounded-full w-8 h-8 flex items-center justify-center font-bold">${step.step}</div>`;
        html += `<div class="ml-4 flex-1">`;
        html += `<h4 class="font-bold text-lg">Replace ${step.algorithm} with ${step.pq_replacement}</h4>`;
        html += `<p class="text-gray-600 text-sm mt-1">${step.description}</p>`;
        html += `<div class="mt-2 text-sm">`;
        html += `<span class="inline-block bg-blue-100 text-blue-800 px-2 py-1 rounded mr-2">${step.nist_standard}</span>`;
        html += `<span class="inline-block bg-gray-100 text-gray-800 px-2 py-1 rounded">${step.occurrences} occurrences</span>`;
        html += `</div></div></div></div>`;
    });

    html += `<div class="bg-blue-50 border border-blue-200 rounded-lg p-4 mt-4">`;
    html += `<p class="text-sm"><strong>Timeline:</strong> ${migrationPlan.timeline_estimate}</p>`;
    html += `<p class="text-sm mt-1"><strong>Complexity:</strong> ${migrationPlan.estimated_complexity}</p>`;
    html += `</div></div>`;

    container.innerHTML = html;
}

// Migrate code — applies PQ replacements and downloads the migrated file
async function migrateCode() {
    if (!currentScanId) {
        alert('No scan results available');
        return;
    }

    const btn = document.getElementById('migrateBtn');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Applying Migration...';

    try {
        const formData = new FormData();
        formData.append('scan_id', currentScanId);

        const response = await fetch(`${API_BASE_URL}/api/migrate/download`, {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            // Trigger file download
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;

            // Get filename from Content-Disposition header if available
            const disposition = response.headers.get('Content-Disposition');
            let filename = `pq_migrated_${currentScanId}.txt`;
            if (disposition) {
                const match = disposition.match(/filename=([^;]+)/);
                if (match) filename = match[1];
            }
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);

            // Also refresh the migration plan display
            const planFormData = new FormData();
            planFormData.append('scan_id', currentScanId);
            const planResponse = await fetch(`${API_BASE_URL}/api/migrate`, {
                method: 'POST',
                body: planFormData
            });
            const planData = await planResponse.json();
            if (planData.success) {
                displayMigrationPlan(planData.migration_plan);
            }

            btn.innerHTML = '<i class="fas fa-check mr-2"></i>Downloaded!';
            setTimeout(() => { btn.innerHTML = originalText; btn.disabled = false; }, 3000);
        } else {
            const err = await response.json();
            alert('Migration failed: ' + (err.detail || 'Unknown error'));
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    } catch (error) {
        console.error('Migration error:', error);
        alert('Failed to apply migration. Please ensure the backend server is running.');
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// Store on blockchain
async function storeOnBlockchain() {
    if (!currentScanId) {
        alert('No scan results available');
        return;
    }

    const btn = document.getElementById('blockchainBtn');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Storing on Blockchain...';

    try {
        const formData = new FormData();
        formData.append('scan_id', currentScanId);

        const response = await fetch(`${API_BASE_URL}/api/blockchain/store`, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (data.success) {

            const explorerUrl = data.explorer_url;

            // ✅ Copy to clipboard
            navigator.clipboard.writeText(explorerUrl);

            // ✅ Show in UI
            const container = document.getElementById("blockchainResult");

            container.innerHTML = `
                <p><b>Transaction Stored ✅</b></p>
                <p>Tx Hash: ${data.tx_hash}</p>
                <p>Block: ${data.block_number}</p>
                <a href="${data.explorer_url}" target="_blank" style="color:blue;">
                    🔗 View on Etherscan
                </a>
            `;

            container.classList.remove("hidden");

            btn.innerHTML = '<i class="fas fa-check mr-2"></i>Stored!';
            setTimeout(() => { btn.innerHTML = originalText; btn.disabled = false; }, 4000);

        } else {
            alert("Blockchain storage failed");
            btn.innerHTML = originalText;
            btn.disabled = false;
        }

    } catch (error) {
        console.error("Blockchain error:", error);
        alert("Failed to store on blockchain");
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}


// Generate report
async function generateReport() {
    if (!currentScanId) {
        alert('No scan results available');
        return;
    }

    const reportType = prompt('Select report type:\n1. RBI\n2. CERT-In\n3. Insurance\n4. General\n\nEnter 1-4:', '1');
    const reportTypes = { '1': 'RBI', '2': 'CERT-In', '3': 'Insurance', '4': 'General' };
    const selectedType = reportTypes[reportType] || 'General';

    const btn = document.getElementById('reportBtn');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin mr-2"></i>Generating Report...';

    try {
        const formData = new FormData();
        formData.append('scan_id', currentScanId);
        formData.append('report_type', selectedType);

        const response = await fetch(`${API_BASE_URL}/api/report/generate`, {
            method: 'POST',
            body: formData
        });

        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `quantum_security_report_${currentScanId}_${selectedType}.pdf`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);

            btn.innerHTML = '<i class="fas fa-check mr-2"></i>Downloaded!';
            setTimeout(() => { btn.innerHTML = originalText; btn.disabled = false; }, 3000);
        } else {
            btn.innerHTML = originalText;
            btn.disabled = false;
        }
    } catch (error) {
        console.error('Report generation error:', error);
        alert('Failed to generate report');
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}

// Helper function to download text as file
function downloadFile(content, filename) {
    const blob = new Blob([content], { type: 'text/plain' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
}

// Scroll functions
function scrollToScan() {
    document.getElementById('scan').scrollIntoView({ behavior: 'smooth' });
}

function scrollToDocs() {
    alert('Documentation section coming soon!');
}
