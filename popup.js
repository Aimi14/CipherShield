document.addEventListener('DOMContentLoaded', function () {
    // Get the open button element
    var openButton = document.getElementById('openButton');

    // Add a click event listener to the open button
    openButton.addEventListener('click', function () {
        // Open a new window with the desired URL
        var newWindow = window.open('http://127.0.0.1:5000', 'File and URL Upload', 'width=400,height=650');
      
        // Ensure that the new window is not null
        if (newWindow) {
            // Focus the new window
            newWindow.focus();
        }
    });

    // Add a click event listener to start the scan
    openButton.addEventListener('click', () => {
        chrome.downloads.search({}, (results) => {
            results.forEach(result => {
                if (result.state === 'complete') {
                    chrome.downloads.onChanged.dispatch({ id: result.id, state: { current: 'complete' } });
                }
            });
        });
    });

    // Listen for scan results from the service worker
    chrome.runtime.onMessage.addListener((message) => {
        if (message.type === 'scanResults') {
            console.log('Received scan results:', message.data); // Add log to check if message is received
            const { suspicious, malicious, undetected } = message.data;
            updateResults('Suspicious', suspicious);
            updateResults('Malicious', malicious);
            updateResults('Undetected', undetected);
        }
    });

    function updateResults(type, value) {
        const resultValueElem = document.getElementById(`value${type}`);
        resultValueElem.textContent = value;
    }
});
