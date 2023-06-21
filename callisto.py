import os
import sys
import time
import subprocess
import platform
import sgrep.controller as sgrep
import openAI.controller as openAI
from prettytable import PrettyTable, ALL


RED   = "\033[1;31m"
YELLOW = "\033[1;33m"
BLUE  = "\033[1;34m"
CYAN  = "\033[1;36m"
WHITE  = "\033[1;37m"
GREEN = "\033[0;32m"
RESET = "\033[0;0m"
BOLD    = "\033[;1m"
REVERSE = "\033[;7m"


class Callisto():

    def __init__(self):

        os = platform.platform()

        if "Windows" in os:
            self.ghidraPath = "C:/Program Files/ghidra_10.1.4_PUBLIC"    # Default
            self.headlessPath = "/support/analyzeHeadless.bat"  # Default
        else:
            self.ghidraPath = "/usr/share/ghidra"
            self.headlessPath = "/support/analyzeHeadless"
        self.decompInterfacePy = "decomp.py"
        self.projectName = "tempProject"
        self.binaryPath = None
        self.configPath = "config.txt"
        self.outputFile = None
        self.aiToggle = False
        self.apiKey = None

        self.config()   # Parse config file
        self.openai = openAI.OpenAI(self)   # Pass self object for reference
        self.sgrep = sgrep.Semgrep()

    
    def controller(self):

        #  Argument Handler
        self.argHandler(sys.argv)

        table = PrettyTable()
        table.field_names = [GREEN + 'Function' + YELLOW, BLUE + 'Semgrep Analysis' + YELLOW, CYAN + 'GPT Analysis' + RESET]
        table.align = 'l'  # Left align the text in column 1
        table.max_width = 60
        table.hrules = ALL

        self.decompiler() # Run Ghidra Decompiler & Friends
        
        print(YELLOW + "[+] Starting Analysis.." + RESET)
        # Extract functions from file
        f = open("output.c", "r")
        contents = f.read()
        functions = contents.split("~~~~~")

        aiAnalysis = ""
        semgrepAnalysis = ""
        for function in functions:
            functionParsed = function.split("\n")
            semgrepAnalysis, semgrepLineNumbs = self.semgrep(function)  # Semgrep Analysis

            # Create line numbers for function output - easy reference
            lineCounter = 1
            functionConsolePrint = ""
            for item in functionParsed:
                if lineCounter > 1:
                    if lineCounter in semgrepLineNumbs:
                        functionConsolePrint += "\n" + RED + str(lineCounter) + RESET + ": " + item    # print Red for lines containing vulns
                    else:
                        functionConsolePrint += "\n" + YELLOW + str(lineCounter) + RESET + ": " + item
                elif lineCounter == 1:
                    if lineCounter in semgrepLineNumbs:
                        functionConsolePrint += RED + str(lineCounter) + RESET + ": " + item    # print Red for lines containing vulns
                    else:
                        functionConsolePrint += YELLOW + str(lineCounter) + RESET + ": " + item
                lineCounter+=1

            if semgrepLineNumbs:  # Only return vuln findings
                print(RED + "[+] Potential Vulnerability Found" + RESET)
                if self.aiToggle:   # if openAI enabled
                    aiAnalysis = self.openAI(function, semgrepAnalysis)  # openAI Analysis
                    table.add_row([functionConsolePrint, semgrepAnalysis, aiAnalysis])
                    if self.outputFile:
                        with open(self.outputFile, 'w') as w:
                            w.write(str(table))
                else:
                    table.add_row([functionConsolePrint, semgrepAnalysis, "AI Analysis Disabled"])
                    if self.outputFile:
                        with open(self.outputFile, 'w') as w:
                            w.write(str(table))

        print(table) # print analysis table


    def decompiler(self):
        args = [
           self.ghidraPath + self.headlessPath,
           self.ghidraPath,
           self.projectName,
           "-import",
           self.binaryPath,
           "-postscript",
           self.decompInterfacePy,
        ]
        try:
            subprocess.run([args[0], args[1], args[2], args[3], args[4], args[5], args[6]], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["rm", "-r", self.ghidraPath + "/" + self.projectName + ".gpr", self.ghidraPath + "/" + self.projectName + ".rep"])    # Remove unnecessary project files to keep it lightweight
            print(YELLOW + "[+] " + "Decompiler Ran Successfully" + RESET)
        except Exception as err:
            print("Decompiler Error: " + str(err))

    def semgrep(self, function):
        return self.sgrep.analyzeC(function)

    def openAI(self, functions, semgrep):
        return self.openai.analyzeC(functions, semgrep)
    
    def config(self):
        f = open(self.configPath, "r")
        content = f.read()
        content = content.split("\n")
        for item in content:
            if "=====" not in item:
                configData = item.split("=")
                if configData[0] == "ghidraPath":
                    self.ghidraPath = configData[1]
                elif configData[0] == "openAIApiKey":
                    self.apiKey = configData[1]
        f.close()

    def argHandler(self, args):
        argIter = True
        tick = 1
        while argIter:
            try:
                if sys.argv[tick] == "-b":  # Path to binary being analyzed
                    self.binaryPath = sys.argv[tick+1]
                elif sys.argv[tick] == "-ai":   # Enable OpenAI
                    self.aiToggle = True
                elif sys.argv[tick] == "-o":    # Write output to file
                    self.outputFile = sys.argv[tick+1]
                elif sys.argv[tick] == "-h":    # Help
                    print("Ex. python callisto.py -b /tmp/test.exe -ai"\
                          "\n -b <path> => path to binary you want to analyze\
                          \n -ai => enable OpenAI analysis")
            except:
                if self.binaryPath is None:
                    print("You must provide path to the binary you want to analyze. Ex. python callisto.py -b /tmp/test.exe -ai")
                break
            tick+=1


Callisto().controller()