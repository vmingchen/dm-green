#! /bin/bash
#
# NOTE: This sample commands below show how to use the power meter. 
#
# Pre-Require: install driver for the power meter. 
#

# Setup the Watts up Pro
wattsup /dev/ttyUSB0  "#C,W,18,1,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0;" s

# Starting a new combination
# Resetting the Wattsup Pro to internal logging every 1 sec
wattsup /dev/ttyUSB0  "#L,W,3,I,0,1;" s

# Benchmark here
echo "Do benchmark here"

# retrieve power and energy data from the wattsup power meter
wattsup /dev/ttyUSB0  "#D,R,0;" r | grep "#d" | cut -d ',' -f 5 > "watts"
wattsup /dev/ttyUSB0  "#D,R,0;" r | grep "#d" | cut -d ',' -f 8 > "energy"
