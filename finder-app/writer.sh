#!/bin/bash

if [ $# -ne 2 ]; then
    printf "Usage ./writer.sh <full_file_path> <write_str>\n"
    exit 1
fi

BASE_DIR=$(dirname "$1")
mkdir -p "$BASE_DIR" && echo "$2" > "$1"
