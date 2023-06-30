import openai
import tiktoken
from prettytable import PrettyTable, ALL


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

class OpenAI():

    def __init__(self, controller):
        self.apiKey = controller.apiKey
        self.vulnExistenceKey = "contains a security vulnerability"
        self.prompt = ""

    def davinci(self, promptData, model):

        # Load your API key from an environment variable or secret management service
        openai.api_key = self.apiKey

        try:
            #response = openai.Completion.create(model="gpt-3.5-turbo-16k", prompt=promptData, temperature=0, max_tokens=400)
            response = openai.ChatCompletion.create(
                model=model,
                messages=[
                    {
                        "role":"system",
                        "content":"You are an advanced security analysis bot verifying semgrep output as well as identifying potential new security vulnerabilities in C functions"
                    },
                    {
                        "role":"user",
                        "content":promptData
                    }
                ]
            )
            resp = response.choices[0].message.content

        except Exception as err:
            return err

        if resp:
            return resp
        else:
            return False

    def analyzeC(self, function, semgrep):


        vulnInspection = ""
    
        self.prompt = "Please start with analyzing this C function for any security vulnerabilities with the highest accuracy possible. Here is the output from the semgrep static analysis tool: " + semgrep + \
                        "Please validate, refute or use this data to aid with the vulnerability analysis of the function. Please identify if any additional vulnerabilities exist and \
                            add any additional findings that may differ from the provided semgrep data.\
                            Here is the C function to analyze: \n" + function
        
        if self.calcToken() > 4096: # Determine model to use based on token calculation of prompt
            vulnInspection = self.davinci(self.prompt, "gpt-3.5-turbo-16k")
            print(Colors['YELLOW'] + "[+] Using gpt-3.5-turbo-16k model for AI analysis" + Colors['RESET'])
        else:
            vulnInspection = self.davinci(self.prompt, "gpt-3.5-turbo")
            print(Colors['YELLOW'] + "[+] Using gpt-3.5-turbo model for AI analysis" + Colors['RESET'])


        return vulnInspection
    

    def calcToken(self):
        enc = tiktoken.get_encoding("cl100k_base")  # Encoding that gpt-3.5 Turbo Uses
        encoded = enc.encode(self.prompt)
        return len(encoded)
