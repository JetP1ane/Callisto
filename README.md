# Callisto
**An Intelligent Automated Binary Vulnerability Analysis Tool**

**Demo:**\
![](callisto_demo.gif)

**Callisto** is an intelligent automated binary vulnerability analysis tool. Its purpose is to autonomously decompile a provided binary and iterate through the psuedo code output looking for potential security vulnerabilities in that pseudo c code. **Ghidra's** headless decompiler is what drives the binary decompilation and analysis portion. The pseudo code analysis is initially performed by the **Semgrep** SAST tool and then transferred to **GPT-3.5-Turbo** for validation of Semgrep's findings, as well as potential identification of additional vulnerabilities.

This tool's intended purpose is to assist with binary analysis and zero-day vulnerability discovery. The output aims to help the researcher identify potential areas of interest or vulnerable components in the binary, which can be followed up with dynamic testing for validation and exploitation. It certainly won't catch everything, but the double validation with Semgrep to GPT-3.5 aims to reduce false positives and allow a deeper analysis of the program.

For those looking to just leverage the tool as a quick headless decompiler, the `output.c` file created will contain all the extracted pseudo code from the binary. This can be plugged into your own SAST tools or manually analyzed.

I owe Marco Ivaldi [@0xdea](https://github.com/0xdea) a huge thanks for his publicly released custom Semgrep C rules as well as his idea to automate vulnerability discovery using semgrep and pseudo code output from decompilers. You can read more about his research here: [Automating binary vulnerability discovery with Ghidra and Semgrep](https://security.humanativaspa.it/automating-binary-vulnerability-discovery-with-ghidra-and-semgrep/)

**Requirements:**
- If you want to use the GPT-3.5-Turbo feature, you must create an API token on [OpenAI](https://platform.openai.com/account/api-keys) and save to the config.txt file in this folder
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
- Semgrep - `pip install semgrep`
- requirements.txt - `pip install -r requirements.txt`
- Ensure the correct path to your Ghidra directory is set in the `config.txt` file

**To Run:**
`python callisto.py -b <path_to_binary> -ai -o <path_to_output_file>`
- `-ai` => enable OpenAI GPT-3.5-Turbo Analysis. Will require placing a valid OpenAI API key in the config.txt file
- `-o` => define an output file, if you want to save the output
- `-ai` and `-o` are optional parameters
-  `-all` will run all functions through OpenAI Analysis, regardless of any Semgrep findings. This flag requires the prerequisite `-ai` flag
- Ex. `python callisto.py -b vulnProgram.exe -ai -o results.txt`
- Ex. (Running all functions through AI Analysis):\
  `python callisto.py -b vulnProgram.exe -ai -all -o results.txt`

**Program Output Example:**\
![](callisto.png)

**Tuning**

When using OpenAI analysis you may wish to tune Semgrep to focus on higher priority issues on the initial run. By default semgrep will flag low severity issues which can result in heavy usage of your OpenAI key for similar issues and lead to rate limiting (depending on free vs paid accounts etc). You can tune semgrep behaviour by modifying sgrep/controller.py to implement severity flags which set a floor level on the analysis. For example, the below will only include High and Medium confidence level rules excluding Low (INFO). 

`sGrepResults = subprocess.run(["semgrep", "--config=sgrep/semgrep-rules-c/c","--severity","ERROR","--severity","WARNING", "--json", "sgrep/semgrep.c"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)`

You can confirm the severity to confidence level rule mappings using the following command: 

`grep -R severity sgrep/semgrep-rules-c`

