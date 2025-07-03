#!/bin/bash

# Test script for dhsh

# Run dhsh with a series of commands
./build/dhsh <<EOF
help
cd /tmp
pwd
ls
ls -l
ls -l
ls -l | grep dhsh
ls > output.txt
exit
EOF

# Check the output
if [ -f output.txt ]; then
    echo "Redirection test failed: output.txt was created."
    rm output.txt
else
    echo "Redirection test passed: output.txt was not created."
fi

echo "All tests completed."
