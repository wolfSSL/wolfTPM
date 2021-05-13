#!/bin/bash

echo "Generating html..."
doxygen Doxyfile
echo "Finished generating html..."

echo "To view the html files use a browser to open the index.html file located at doc/html/index.html"
