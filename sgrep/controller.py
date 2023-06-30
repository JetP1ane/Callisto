import json
import subprocess


Colors = {
    "RED": "\033[1;31m",
    "YELLOW": "\033[1;33m",
    "BLUE": "\033[1;34m",
    "CYAN": "\033[1;36m",
    "WHITE": "\033[1;37m",
    "GREEN": "\033[0;32m",
    "RESET": "\033[0;0m",
    "BOLD":"\033[;1m",
    "REVERSE": "\033[;7m",
}

class Semgrep():

    def __init__(self):
        self.cmd = "semgrep --config=sgrep/semgrep-rules-c/c semgrep.c"

    def analyzeC(self, function):
        # Write function to file for analysis
        f = open("sgrep/semgrep.c", "w")
        f.write(function)
        f.close()

        resultsConcat = ""
        resultsLineNum = []
        sGrepResults = subprocess.run(["semgrep", "--config=sgrep/semgrep-rules-c/c", "--json", "sgrep/semgrep.c"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sGrepResults = sGrepResults.stdout.decode('utf-8')
        sGrepResults = json.loads(sGrepResults)

        tick = 0
        for item in sGrepResults["results"]:
            vulnMessage = sGrepResults["results"][tick]["extra"]["message"]
            lineNumber = sGrepResults["results"][tick]["start"]["line"]
            resultsLineNum.append(lineNumber)
            if tick != 0:
                resultsConcat = resultsConcat + "\n\n" + Colors['GREEN'] + "Finding: " + Colors['RESET'] + vulnMessage + \
                    "\n" + Colors['WHITE'] + "Line: " + Colors['RESET'] + Colors['RED'] + str(lineNumber) + Colors['RESET']
            else:
                resultsConcat = resultsConcat + Colors['GREEN'] + "Finding: " + Colors['RESET'] + vulnMessage + \
                    "\n" + Colors['WHITE'] + "Line: " + Colors['RESET'] + Colors['RED'] + str(lineNumber) + Colors['RESET']
            tick+=1

        return(resultsConcat, resultsLineNum)
