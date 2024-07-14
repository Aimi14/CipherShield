document.addEventListener('DOMContentLoaded', () => { 
function checkScanStatus() {
    fetch('/scan_file', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            const url = new URL(window.location.origin + '/display_results');
            url.searchParams.append('suspicious', data.suspicious);
            url.searchParams.append('malicious', data.malicious);
            url.searchParams.append('undetected', data.undetected);
            window.location.href = url.toString();
        })
        .catch(error => {
            document.getElementById('scan-status').textContent = 'An error occurred during the scan.';
            console.error('Error during scan:', error);
        });
}
});

// Start the scan process when the page loads
window.onload = checkScanStatus;
