from flask import Flask, request, render_template, jsonify
from flask_cors import CORS
import requests
import time
import sys
import base64

app = Flask(__name__)
CORS(app)

def get_virustotal_headers():
    return {
        "accept": "application/json",
        "x-apikey": "d544dcd510331fcd2104b1476c691f64720230df453cdd1ce72a8b79e8a5c5b9"
    }

@app.route('/scan_url', methods=['POST'])
def scan_url():
    url = request.form['url']
    headers = {
        "accept": "application/json",
        "x-apikey": "d544dcd510331fcd2104b1476c691f64720230df453cdd1ce72a8b79e8a5c5b9",
        "content-type": "application/x-www-form-urlencoded"
    }
    payload = { "url": url }

    # Submit URL for scanning
    scan_response = requests.post("https://www.virustotal.com/api/v3/urls", data=payload, headers=headers)
    
    if scan_response.status_code == 200:
        scan_data = scan_response.json()
        url_id = scan_data['data']['id']

        # Base64 encode the URL to use it in the report request
        encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        # Fetch analysis report
        report_url = f"https://www.virustotal.com/api/v3/urls/{encoded_url}"
        report_response = requests.get(report_url, headers=headers)

        if report_response.status_code == 200:
            report_data = report_response.json()
            results = {
                'suspicious': report_data['data']['attributes']['last_analysis_stats']['suspicious'],
                'malicious': report_data['data']['attributes']['last_analysis_stats']['malicious'],
                'undetected': report_data['data']['attributes']['last_analysis_stats']['undetected']
            }
            is_malicious = results['malicious'] > 0
            return render_template('result.html', results=results, is_malicious=is_malicious, url=url)
        else:
            return render_template('upload.html', error_message="Error fetching report")
    else:
        return render_template('upload.html', error_message="Error scanning URL")

@app.route('/scan_file', methods=['POST'])
def scan_file():
    print("Working to scan the file")

    if 'file' not in request.files:
        print("No file part in request") 
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        print("No selected file")
        return jsonify({'error': 'No selected file'}), 400
    
    print("File received: ", file.filename)
    
    url = 'https://www.virustotal.com/api/v3/files'
    files = {'file': (file.filename, file.read(), file.content_type)}
    headers = get_virustotal_headers()

    print("Headers accepted")
    
    response = requests.post(url, files=files, headers=headers)
    if response.ok:
        upload_data = response.json()
        file_id = upload_data['data']['id']
        analysis_url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
        analysis_headers = get_virustotal_headers()

        while True:
            print("Waiting for 60 seconds before requesting the analysis results", file=sys.stdout)
            time.sleep(60)
            analysis_response = requests.get(analysis_url, headers=analysis_headers)
            print(analysis_response.status_code, file=sys.stdout)
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                attributes = analysis_data['data']['attributes']
                status = attributes['status']
                print(status, file=sys.stdout)
                if status == 'completed':
                    results = {
                        'suspicious': attributes['stats']['suspicious'],
                        'malicious': attributes['stats']['malicious'],
                        'undetected': attributes['stats']['undetected']
                    }
                    return jsonify(results)  # For service_worker.js
                else:
                    print("Analysis status: {}. Waiting for analysis to complete...".format(status), file=sys.stdout)
                    time.sleep(10)
            else:
                return jsonify({'error': 'Failed to get analysis results', 'status': analysis_response.status_code}), 500

    return jsonify({'error': 'Failed to scan the file', 'status': response.status_code}), 500

# Route for scan process page
@app.route('/scan_process')
def scan_process():
    return render_template('console.html')

@app.route('/display_results')
def display_results():
    suspicious = request.args.get('suspicious')
    malicious = request.args.get('malicious')
    undetected = request.args.get('undetected')
    return render_template('result.html', results={
        'suspicious': suspicious,
        'malicious': malicious,
        'undetected': undetected
    })

@app.route("/", methods=["GET", "POST"])
def upload_file():
   
  # Handle file upload
    if request.method == "POST":
        uploaded_file = request.files["file"]
        if uploaded_file.filename != "":
            allowed_extensions = {'pdf','docx', 'xlsx', 'pptx'}
            file_extension = uploaded_file.filename.split('.')[-1].lower()
            if file_extension in allowed_extensions:
             # Step 1: Upload the file to VirusTotal
                upload_url = "https://www.virustotal.com/api/v3/files"
                headers = get_virustotal_headers()
                files = {"file": (uploaded_file.filename, uploaded_file.stream)}

                upload_response = requests.post(upload_url, files=files, headers=headers)
                if upload_response.status_code == 200:
                    upload_data = upload_response.json()
                    file_id = upload_data['data']['id']

                    # Step 2: Wait for analysis to complete
                    analysis_url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
                   

                    while True:
                        time.sleep(60)
                        analysis_response = requests.get(analysis_url, headers=headers)
                        if analysis_response.status_code == 200:
                            analysis_data = analysis_response.json()
                            attributes = analysis_data['data']['attributes']
                            status = attributes['status']

                            if status == 'completed':
                                results = {
                                    'suspicious': attributes['stats']['suspicious'],
                                    'malicious': attributes['stats']['malicious'],
                                    'undetected': attributes['stats']['undetected']
                                }
                                is_malicious = results['malicious'] > 0
                                file_url = f"Downloads/{uploaded_file.filename}"  # Adjust this path based on how you serve files
                                return render_template("result.html", results=results, is_malicious=is_malicious, file_url=file_url)
                            elif status == 'queued':
                                continue
                            else:
                                return render_template("upload.html", error_message=f"Unexpected analysis status: {status}")
                        else:
                            return render_template("upload.html", error_message=f"Failed to get analysis results. Status code: {analysis_response.status_code}")
                else:
                    return render_template("upload.html", error_message=f"Failed to upload the file. Status code: {upload_response.status_code}")
            else:
                return render_template("upload.html", error_message="Unsupported file type. Please upload a PDF, Word, Excel, or PowerPoint file.")
    return render_template("upload.html")


if __name__ == "__main__":
    app.run(debug=True)
