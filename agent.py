import sys
import os
import re
import subprocess
import anthropic

# -----------------------------------------------------------------------------
# CONFIGURATION
# -----------------------------------------------------------------------------
ANTHROPIC_API_KEY =""
MODEL_NAME = "claude-sonnet-4-20250514" 
MAX_STEPS = 20

# -----------------------------------------------------------------------------
# SYSTEM PROMPT
# -----------------------------------------------------------------------------
SYSTEM_PROMPT_TEMPLATE = """You are an expert CTF Pwn Agent. Your goal is to capture the flag.

### CONTEXT
- **Challenge Dir:** {cwd}
- **Files:** {file_list}
- **Binary Protections:** {checksec}

### AVAILABLE TOOLS
1. `run_command(command)`: Execute shell commands (ls, checksec, ropper, cat).
2. `decompile(function_name)`: Decompile a function using radare2/r2dec.
3. `run_exploit(script_content)`: Write and execute a Python script using pwntools.

### STRATEGY GUIDELINES
1. **Analyze Protections:**
   - **NX Enabled?** You MUST use ROP (Return Oriented Programming). Do NOT try shellcode.
   - **No Canary?** You can overflow the stack to overwrite the return address.
2. **Analyze Code:** Use `decompile` to find vulnerabilities (gets, strcpy, printf).
3. **Exploit:**
   - Write a `pwntools` script to exploit the binary.
   - Use `process('./binary')` for local testing.
   - **CRITICAL:** Your script MUST print the flag to stdout so I can read it.
   - If the script fails, analyze the error and TRY AGAIN.

### RULES
- **DO NOT** read `flag.txt` directly.
- **ALWAYS** include `p.recvall(timeout=2)` or `p.interactive()` at the end of your scripts.

YOU CAN'T DO THE PROGRAM WITHOUT EXPLOITING IT - THIS SHOULD BE FUNDATEMENT NO READING THE FALG
"""

# -----------------------------------------------------------------------------
# WRITE-UP GENERATOR
# -----------------------------------------------------------------------------
class WriteUpGenerator:
    def __init__(self):
        self.steps = []
        self.final_exploit_script = None

    def log_command(self, cmd):
        if "ls" not in cmd and "file" not in cmd: # Filter noise
            self.steps.append(f"# Shell Command\n# $ {cmd}")

    def log_exploit(self, script):
        self.final_exploit_script = script

    def print_writeup(self, flag):
        print("\n" + "="*80)
        print(f"🚩 FLAG CAPTURED: {flag}")
        print("="*80)
        print("\n📝 EXAM WRITE-UP / REPRODUCTION SCRIPT")
        print("To solve this challenge, the agent performed the following analysis and exploitation:")
        print("-" * 40)
        
        # Print the reconstruction
        print("```python")
        print("from pwn import *")
        print("import os")
        print("")
        print("# --- Step 1: Analysis & Setup ---")
        for step in self.steps:
            print(step)
        
        if self.final_exploit_script:
            print("\n# --- Step 2: Final Exploit Script ---")
            # Remove imports if they are redundant to avoid clutter
            lines = self.final_exploit_script.split('\n')
            for line in lines:
                if not line.startswith("from pwn import") and not line.startswith("import sys"):
                    print(line)
        else:
            print("# (No complex exploit script was needed)")
            
        print("```")
        print("="*80)

# -----------------------------------------------------------------------------
# AGENT CLASS
# -----------------------------------------------------------------------------
class Agent:
    def __init__(self, challenge_dir):
        self.client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
        self.challenge_dir = challenge_dir
        self.writeup = WriteUpGenerator()
        self.messages = []
        os.chdir(challenge_dir)

    def _run_cmd(self, cmd):
        try:
            res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=10)
            return res.stdout.strip()
        except Exception as e:
            return f"Error: {e}"

    def run_command(self, command):
        print(f"💻 CMD: {command}")
        self.writeup.log_command(command)
        return self._run_cmd(command)

    def run_exploit(self, script_content):
        print(f"🧪 EXPLOIT: Running Python Script ({len(script_content)} bytes)...")
        filename = "solve_attempt.py"
        with open(filename, "w") as f:
            f.write(script_content)
        
        output = self._run_cmd(f"python3 {filename}")
        
        # If this exploit found the flag, save it as the final solution
        if "csawctf{" in output or "flag{" in output:
             self.writeup.log_exploit(script_content)
             
        return output

    def decompile(self, function_name="main"):
        print(f"📜 DECOMPILE: {function_name}")
        # Find binary
        files = self._run_cmd("ls")
        binary = next((f for f in files.split() if os.access(f, os.X_OK) and not f.endswith('.py')), None)
        
        if not binary: return "Error: No binary found."
        
        # Try pdd then pdf
        out = self._run_cmd(f"r2 -e bin.relocs=true -A -q -c 'pdd @ {function_name}' {binary}")
        if not out or "Error" in out:
            out = self._run_cmd(f"r2 -A -q -c 'pdf @ {function_name}' {binary}")
        return out

    def gather_recon(self):
        print("🔍 Pre-Flight Recon...")
        files = self._run_cmd("ls -F")
        binary = next((line.split(':')[0] for line in self._run_cmd("file *").split('\n') if "ELF" in line), None)
        checksec = self._run_cmd(f"checksec --file={binary}") if binary else "N/A"
        return files, checksec

    def step(self):
        try:
            response = self.client.messages.create(
                model=MODEL_NAME,
                max_tokens=2048,
                system=self.system_prompt,
                messages=self.messages,
                tools=[
                    {"name": "run_command", "description": "Run shell command", "input_schema": {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}},
                    {"name": "run_exploit", "description": "Run pwntools script", "input_schema": {"type": "object", "properties": {"script_content": {"type": "string"}}, "required": ["script_content"]}},
                    {"name": "decompile", "description": "Decompile function", "input_schema": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"]}}
                ]
            )
        except Exception as e:
            print(f"❌ API Error: {e}")
            return "STOP"

        self.messages.append({"role": "assistant", "content": response.content})
        tool_use = next((b for b in response.content if b.type == "tool_use"), None)

        if not tool_use: return "CONTINUE"

        tool_name = tool_use.name
        res = ""
        
        if tool_name == "run_command": res = self.run_command(tool_use.input["command"])
        elif tool_name == "run_exploit": res = self.run_exploit(tool_use.input["script_content"])
        elif tool_name == "decompile": res = self.decompile(tool_use.input.get("function_name", "main"))

        # Check for flag
        match = re.search(r'(csawctf|flag|CTF)\{.*?\}', res)
        if match:
            self.writeup.print_writeup(match.group(0))
            return "FOUND"

        self.messages.append({"role": "user", "content": [{"type": "tool_result", "tool_use_id": tool_use.id, "content": res}]})
        return "CONTINUE"

    def run(self):
        files, checksec = self.gather_recon()
        self.system_prompt = SYSTEM_PROMPT_TEMPLATE.format(cwd=os.getcwd(), file_list=files, checksec=checksec)
        self.messages.append({"role": "user", "content": "Start analysis."})
        
        for i in range(MAX_STEPS):
            print(f"\n--- Step {i+1} ---")
            if self.step() == "FOUND": return
            
        print("❌ Failed to find flag.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python agent.py <challenge_dir>")
        sys.exit(1)
    Agent(sys.argv[1]).run()