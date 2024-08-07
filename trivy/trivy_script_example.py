import json
from datetime import datetime

def extract_vulnerabilities(input_file, output_file):
    try:
        # Read the input JSON file
        with open(input_file, 'r') as infile:
            data = json.load(infile)

        # Prepare a list to hold the extracted logs
        logs = []

        # Iterate through the vulnerabilities
        for item in data:
            if 'Vulnerabilities' in item:
                for vulnerability in item['Vulnerabilities']:
                    vulnerability_id = vulnerability.get('VulnerabilityID')
                    severity = vulnerability.get('Severity')
                    if vulnerability_id and severity:
                        # Get the current timestamp in the desired format
                        timestamp = datetime.now().strftime('%Y-%m-%dT%H:%M:%S.%f%z')
                        # Create a log entry in the desired format
                        log_entry = {
                            "program_name": "trivy-scan",
                            "timestamp": timestamp,
                            "vulnerabilityid": vulnerability_id,
                            "severity": severity
                        }
                        logs.append(log_entry)

        # Write the logs to the output JSON file
        with open(output_file, 'w') as outfile:
            for log in logs:
                json.dump(log, outfile)
                outfile.write('\n')  # Write each log entry on a new line

        print(f"Extracted {len(logs)} vulnerabilities to {output_file}")

    except Exception as e:
        print(f"An error occurred: {e}")

# Specify the input and output file paths
input_file = 'trivy_results_i.json'  # Replace with your input file path
output_file = 'trivy_results_o.json'  # Replace with your desired output file path

# Run the extraction
extract_vulnerabilities(input_file, output_file)