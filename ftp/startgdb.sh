#!/bin/bash
gdb -x gdbinit --pid $(ps -aux | grep -i has-ftp | grep -v 'grep' | head -n1 | tr -s ' ' | cut -d ' ' -f2)
