
#!/bin/bash
find ~ -maxdepth 1 -type f -name "*.txt"
files=$(find ~ -maxdepth 1 -type f -name "*.txt")
du -bc $files | tail -n1 | cut -f1
wc -l $files | tail -n1 | cut -f1
