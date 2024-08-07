#!/bin/bash

# Define the target to scan (e.g., a Docker image or a directory)
TARGET="vulnerables/web-dvwa"

trivy image --format json --output /var/ossec/logs/trivy_results_o.json $TARGET 2>&1