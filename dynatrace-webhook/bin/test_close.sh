#!/usr/bin/env bash

echo "Sending request to localhost:5000"
echo "Response:"
curl localhost:5000/sdm -d '{"CustomID": "ID 1515", "ProblemID": "999", "State": "RESOLVED", "ProblemDetailsText": "Dynatrace problem notification test run details", "ProblemTitle": "Dynatrace problem notification test run"}'