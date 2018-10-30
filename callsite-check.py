#!/usr/bin/python2
import r2pipe
import sys

if len(sys.argv) != 2:
    raise SystemExit

exe = sys.argv[1]
r2 = r2pipe.open(exe)
mvtext = r2.cmdj('pdj 2 @ section.multiverse_text')

jump = mvtext[0]
guard = mvtext[1]
print(exe + " & " + jump['disasm'] + " & " + guard['opcode'])
