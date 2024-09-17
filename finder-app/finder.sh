#!/bin/bash

if [ $# -ne 2 ]; then
    printf "Usage ./finder.sh <filesdir> <searchstr>\n"
    exit 1
fi

if [ -d "$1" ]; then
    FILE_NUM=$(find "$1" -type f | wc -l)
    LINE_NUM=$(grep -r "$2" "$1"/* | wc -l)
    echo "The number of files are $FILE_NUM and the number of matching lines are $LINE_NUM"
else
    printf "Argument 1 does not represent a directory on the file system!\n"
    exit 1
fi
