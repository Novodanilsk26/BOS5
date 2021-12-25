#!/bin/bash
grep "000000" ~/bash.txt > /tmp/zeros
grep -v "000000" ~/bash.txt > /tmp/nonzeros
cat /tmp/zeros | head -n10
cat /tmp/zeros | tail -n10
cat /tmp/nonzeros | head -n10
cat /tmp/nonzeros | tail -n10
