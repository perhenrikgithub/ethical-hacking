Here is a practice exam file based on your slides. As requested, I have focused heavily on the topics that did not have existing quizzes (Intro, Firewalls, Web Security, Smart Contracts, and Reverse Engineering) while providing a few review questions for the others.

Save this as a `.md` file or simply write your answers in a text editor. When you are ready, paste your answers back to me, and I will correct them.

---

# Ethical Hacking & Security Practice Exam

## Section 1: Introduction to Ethical Hacking & Threat Modeling

_(Focus Area: No previous quiz provided)_

**Q1.1 (Short Answer)**
Define the difference between a **Red Team** and a **Blue Team** in the context of a company's security exercise.

**Q1.2 (Multiple Choice)**
In the context of Threat Modeling, what does the acronym **STRIDE** stand for?
a. Security, Threat, Risk, Integrity, Denial, Elevation
b. Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege
c. Spoofing, Testing, Risk, Information Disclosure, Detection, Elevation of Privilege
d. Scanning, Targeting, Reconnaissance, Intrusion, Data Exfiltration, Evasion

**Q1.3 (Short Answer)**
What is the fundamental formula used to calculate **Risk** in threat analysis?

**Q1.4 (Multiple Choice)**
Which of the following is an **asset-centric** approach to threat modeling?
a. Creating a list of threat actors (motive, means, opportunity).
b. Drawing a diagram of the application and ranking threats using STRIDE.
c. Creating a list of assets, drawing data flows, and checking for threats against each element.
d. Using the OWASP Top 10 to blindly patch code.

**Q1.5 (Short Answer)**
Explain the concept of **Hacktivism**. Which category of hacker (Hat color) is most often associated with it?

---

## Section 2: Sniffing, Spoofing, and Layer 4 Attacks

_(Review Area)_

**Q2.1 (Short Answer)**
In a TCP Session Hijacking attack, what specific piece of information must the attacker successfully guess or sniff to inject malicious packets into an active connection?

**Q2.2 (Multiple Choice)**
Which of the following is a countermeasure against **Source Routing Attacks**?
a. Enforcing a minimum packet size.
b. Discarding packets that have the source routing option enabled.
c. using a Switch instead of a Hub.
d. Randomizing the Initial Sequence Number (ISN).

**Q2.3 (Short Answer)**
Why is a random Initial Sequence Number (ISN) crucial for TCP security?

---

## Section 3: Firewall Security

_(Focus Area: No previous quiz provided)_

**Q3.1 (Multiple Choice)**
What is the primary purpose of a **Demilitarized Zone (DMZ)**?
a. To encrypt all traffic leaving the internal network.
b. To block all traffic from the internet.
c. To create a network segment connecting the untrusted world to the internal private network, hosting public-facing servers.
d. To allow the Red Team to attack without damaging the real network.

**Q3.2 (Short Answer)**
Explain the difference between a **Default Discard** policy and a **Default Forward** policy in packet filtering. Which is more secure?

**Q3.3 (Multiple Choice)**
An attacker deliberately creates very small IP packets to split the TCP header across multiple fragments. The goal is to push the TCP flags into the second fragment to bypass a firewall that only checks the first fragment. What is this attack called?
a. Source Routing Attack
b. Tiny Fragments Attack
c. IP Spoofing
d. SYN Flood

**Q3.4 (Short Answer)**
In the context of Packet Filtering, what are the three standard actions a firewall can take regarding a packet?

**Q3.5 (Multiple Choice)**
Which limitation is specific to a standard **Packet Filtering Firewall**?
a. It cannot inspect the payload of the application layer (e.g., HTTP content).
b. It cannot check IP addresses.
c. It introduces too much latency for modern networks.
d. It cannot be placed on a router.

---

## Section 4: Web Security (XSS, CSRF, SQLi)

_(Focus Area: No previous quiz provided)_

**Q4.1 (Multiple Choice)**
Which type of **XSS** (Cross-Site Scripting) involves the malicious script being permanently saved on the target server's database?
a. Reflected XSS
b. DOM-Based XSS
c. Stored XSS
d. Server-Side XSS

**Q4.2 (Short Answer)**
In a **DOM-Based XSS** attack, does the malicious payload necessarily reach the server? Explain briefly why or why not.

**Q4.3 (Short Answer)**
What is the "Fundamental Cause" of both SQL Injection and XSS attacks?

**Q4.4 (Multiple Choice)**
You are reviewing a PHP login script:
`$sql = "SELECT * FROM users WHERE name='$name' AND pass='$pass'";`
If an attacker inputs `' OR '1'='1` into the name field, what happens to the query logic?
a. The database crashes.
b. The query becomes `SELECT * FROM users WHERE name='' OR '1'='1' ...`, effectively returning true for all rows (or the first row).
c. The query fails because of a syntax error.
d. The password field is automatically encrypted.

**Q4.5 (Multiple Choice)**
Which of the following is the most effective defense against **SQL Injection**?
a. Sanitizing input by removing specific characters like `'` and `-`.
b. Using Prepared Statements (separation of code and data).
c. Hiding the database error messages.
d. Using a complex database password.

**Q4.6 (Short Answer)**
Describe how a **CSRF (Cross-Site Request Forgery)** attack works. Why does the server accept the malicious request?

**Q4.7 (Multiple Choice)**
Which of the following is a valid mitigation technique for **CSRF**?
a. Using HTTPS for all connections.
b. Input validation on the client side.
c. Implementing Anti-CSRF Tokens (Secret Tokens) in forms.
d. Disabling Javascript in the browser.

**Q4.8 (Multiple Choice)**
Regarding **SameSite Cookies**, which setting ensures the cookie is _never_ sent with cross-site requests?
a. SameSite=Lax
b. SameSite=Strict
c. SameSite=None
d. SameSite=Secure

---

## Section 5: Smart Contracts Security

_(Focus Area: No previous quiz provided)_

**Q5.1 (Short Answer)**
What is the key difference between a generic **Distributed Ledger Technology (DLT)** and a **Blockchain**?

**Q5.2 (Multiple Choice)**
Smart contracts on Ethereum are compiled into bytecode and executed by the:
a. Miner's CPU directly.
b. Ethereum Virtual Machine (EVM).
c. Web3 JavaScript API.
d. Proof of Work algorithm.

**Q5.3 (Short Answer)**
Why is "Immutability" in blockchain both a security feature and a security risk when it comes to Smart Contracts?

**Q5.4 (Multiple Choice)**
What triggers the execution of a function within a Smart Contract?
a. A transaction sent to the contract's address with specific data.
b. The mining of a new block automatically triggers all contracts.
c. A manual approval by the Ethereum Foundation.
d. A CRON job running on the blockchain nodes.

---

## Section 6: Reverse Engineering

_(Focus Area: No previous quiz provided)_

**Q6.1 (Multiple Choice)**
Which register in the x86 architecture points to the **top of the stack**?
a. EBP / RBP
b. EIP / RIP
c. ESP / RSP
d. EAX / RAX

**Q6.2 (Short Answer)**
Explain the difference between **Static Analysis** and **Dynamic Analysis**.

**Q6.3 (Multiple Choice)**
Which assembly instruction performs a subtraction but _throws away the result_, only updating the FLAGS register (often used before a jump)?
a. SUB
b. MOV
c. LEA
d. CMP

**Q6.4 (Short Answer)**
In the context of the ELF format, what is the purpose of the `.text` section?

**Q6.5 (Multiple Choice)**
What is the purpose of the **Function Prologue** (e.g., `push ebp; mov ebp, esp`)?
a. To clean up the stack before returning.
b. To set up a new stack frame for the called function.
c. To jump to the next instruction.
d. To allocate memory on the heap.

**Q6.6 (Short Answer)**
If you see the instruction `XOR EAX, EAX`, what is the resulting value in the EAX register?

**Q6.7 (Multiple Choice)**
Why is **Decompilation** (converting binary to source code) considered generally "undecidable" or difficult?
a. Because assembly language is too complex.
b. Because high-level information (variable names, comments, structure) is lost during compilation.
c. Because disassemblers are illegal.
d. Because modern CPUs encrypt the binary.

---

## Section 7: Software Security (Buffer Overflow & Protections)

_(Focus Area: Partial previous coverage, adding depth)_

**Q7.1 (Short Answer)**
Explain how **Stack Canaries** protect against buffer overflows. What happens if the canary value is modified?

**Q7.2 (Multiple Choice)**
If a system implements **ASLR (Address Space Layout Randomization)**, which part of the attack becomes significantly more difficult?
a. Injecting the shellcode.
b. Finding the address of the stack/shellcode to jump to.
c. Crashing the program.
d. Generating a NOP sled.

**Q7.3 (Multiple Choice)**
In a **Format String Attack**, what does the `%n` format specifier do?
a. Prints the number of characters written so far.
b. Reads a hex value from the stack.
c. Writes the number of characters printed so far into the memory address pointed to by the argument.
d. Crashes the program immediately.

**Q7.4 (Short Answer)**
Why is `strcpy()` considered unsafe compared to `strncpy()`?
