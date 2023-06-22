import sys
from  ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


# get the current program
# here currentProgram is predefined

program = currentProgram
decompinterface = DecompInterface()
decompinterface.openProgram(program)
functions = program.getFunctionManager().getFunctions(True)
monitor = ConsoleTaskMonitor()

c = open("output.c", "w+")
f = open("callGraph.txt", "w+")

for function in list(functions):
    callingFuncs = function.getCalledFunctions(monitor)
    f.write("Function: " + function.getName() + str(callingFuncs))
    f.write("\n\r")
    # decompile each function
    tokengrp = decompinterface.decompileFunction(function, 0, monitor)
    c.write(tokengrp.getDecompiledFunction().getC())
    c.write("~~~~~")

f.close()
c.close()
