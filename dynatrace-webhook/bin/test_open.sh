#!/usr/bin/env bash

echo "Sending request to localhost:5000"
echo "Response:"
curl localhost:5000/sdm -d '{"Pcat": "400373", "CustomID": "ID 1515", "ProblemID": "999", "State": "OPEN", "ProblemDetailsText": "Dynatrace problem notification test run details", "ProblemTitle": "Dynatrace problem notification test run"}'