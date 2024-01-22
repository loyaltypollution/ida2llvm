#!/bin/bash

# Select file from test/idb
files="$(ls -A ./tests/idb)"
echo "Select an valid idb:"

# Use the select statement to present the user with a numbered list of files
select filename in ${files}; do
    # If the user selects a valid file, echo its name
    if [[ -n "$filename" ]]; then
        # Make directory for script output
        mkdir -p ./tests/ll ./tests/log

        wine ~/.wine/ida/idat64.exe -A -S"./docker_entrypoint.py" "./tests/idb/$filename" -t 2>/dev/null
    else
        echo "Invalid selection"
    fi
    break
done

# Display results
echo 'results written to ./tests/ll'