chrome.downloads.onChanged.addListener(async (downloadDelta) => {
    if (downloadDelta.state && downloadDelta.state.current === 'complete') {
        console.log('Download complete, starting scan process...');
        try {
            const results = await chrome.downloads.search({ id: downloadDelta.id });
            if (results && results[0]) {
                const fileUrl = results[0].url;
                console.log(`Downloaded file URL: ${fileUrl}`);
                
                const response = await fetch(fileUrl);
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                console.log('File fetched successfully.');
  
                const blob = await response.blob();
                const file = new File([blob], results[0].filename, { type: blob.type });
                const formData = new FormData();
                formData.append("file", file);

                // Open a new tab with the scan process page
                console.log('File prepared for scanning, sending to server...');
                const scanProcessUrl = new URL("http://127.0.0.1:5000/scan_process");
                
                // Create scan process tab
                chrome.tabs.create({ url: scanProcessUrl.toString() }, async (tab) => {
                    const scanResponse = await fetch("http://127.0.0.1:5000/scan_file", {
                        method: "POST",
                        body: formData
                    });
                    if (!scanResponse.ok) {
                        throw new Error(`HTTP error! status: ${scanResponse.status}`);
                    }
                    console.log('File sent to server for scanning, waiting for response...');
      
                    const data = await scanResponse.json();
                    console.log("Scan results received:", data);
      
                    // Open a new tab with the results page
                    const url = new URL("http://127.0.0.1:5000/display_results");
                    url.searchParams.append("suspicious", data.suspicious);
                    url.searchParams.append("malicious", data.malicious);
                    url.searchParams.append("undetected", data.undetected);
                    chrome.tabs.create({ url: url.toString() }, () => {
                        // Close the scan process tab
                        chrome.tabs.remove(tab.id);
                    });
                });
            } else {
                console.log('No results found for the completed download.');
            }
        } catch (error) {
            console.error('Error in scanning file:', error);
            chrome.notifications.create({
                type: 'basic',
                iconUrl: chrome.runtime.getURL('icon48.png'),
                title: 'Scan Error',
                message: `Error: ${error.message}`
            }, () => {
                console.log("Error notification created.");
            });
        }
    }
});
