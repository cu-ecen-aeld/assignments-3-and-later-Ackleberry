# Support for cross-compilation.  You should be able to generate an application for the native build
# platform when GNU make variable CROSS_COMPILE is not specified on the make command line. 
# When CROSS_COMPILE is specified with aarch64-none-linux-gnu- (note the trailing -)your makefile 
# should compile successfully using the cross compiler installed in step 1.

CC := $(CROSS_COMPILE)gcc

writer: writer.c
	$(CC) -Wall -Wextra -O2 writer.c -o writer
	chmod +x $@

.PHONY: clean
clean:
	rm -f writer
