#!/bin/bash

# Test script for dhsh

# Run dhsh with a series of commands
./build/dhsh <<EOF > /tmp/dhsh_test_output.txt
help
cd /tmp
pwd
ls
ls -l
ls -l
ls -l | grep dhsh
ls > /tmp/output.txt
exit
EOF

# Check the output
if [ -f /tmp/output.txt ]; then
    echo "Redirection test passed: output.txt was created."
    rm /tmp/output.txt
else
    echo "Redirection test failed: output.txt was not created."
fi

# Check main output
if [ -f /tmp/dhsh_test_output.txt ]; then
    echo "Main output test passed."
    rm /tmp/dhsh_test_output.txt
else
    echo "Main output test failed."
fi

echo "All tests completed."
