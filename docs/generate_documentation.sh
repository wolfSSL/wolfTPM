#!/bin/bash

CURRDIR=${PWD##*/}
if [ "$CURRDIR" != "docs" ]; then
    echo "Please run from the ./docs directory"
    exit 1
fi

# Run from ./docs
echo "Generating html..."
doxygen Doxyfile
echo "Finished generating html..."

echo "To view the html files use a browser to open the index.html file located at docs/html/index.html"
