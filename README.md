# Password Strength Checker + Breach Lookup

A Python command-line project that estimates password strength and checks the Have I Been Pwned (HIBP) Pwned Passwords dataset. The breach lookup sends a hash prefix instead of the password or its full hash.

## Features

- Strength score from 0 to 5, with feedback about length, repeated characters, and common patterns
- Character-pool estimate based on length and character types
- Breach lookup using the HIBP range API with k-anonymity
- Hidden input in a terminal; a visible-input prompt in IDE consoles that do not support it
- A request timeout and handling for network and HTTP errors

## Setup and run

Requires Python 3.9 or newer and an internet connection for breach lookups. No HIBP API key is required for the Pwned Passwords range API.

```bash
git clone https://github.com/jalenowens766-cmd/password-checker.git
cd password-checker
python -m venv .venv
```

Activate the virtual environment on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Or on macOS/Linux:

```bash
source .venv/bin/activate
```

Install the dependency and start the tool:

```bash
python -m pip install -r requirements.txt
python password_checker.py
```

If PyCharm's Run console displays the visible-input prompt, use its Terminal tab for hidden input. Use made-up passwords when demonstrating or taking screenshots.

## How the breach lookup works

1. Hash the password locally with SHA-1.
2. Send only the first five hexadecimal hash characters to HIBP over HTTPS.
3. Receive hash suffixes and occurrence counts for that prefix.
4. Compare the full hash locally and report the matching count.

The request uses `Add-Padding: true` to reduce information leakage from response size. HIBP still receives the hash prefix and normal connection metadata, such as the requesting IP address. SHA-1 is used to match this API's dataset, not to store passwords.

Reference: [HIBP Pwned Passwords API documentation](https://haveibeenpwned.com/API/v3#PwnedPasswords).

## Limitations

The score is a learning-oriented heuristic. The character-pool calculation assumes random selection and can overestimate predictable passwords and phrases; it is not a measured entropy value or a cracking-time prediction. The common-password and pattern lists are intentionally small, and character classes primarily target ASCII.

A matching count is the number of occurrences in the dataset, not the number of distinct breaches. A missing match does not prove that a password is safe, unique, or uncompromised. A failed lookup leaves breach status unknown. The script does not write entered passwords to files or print them in its results, but an IDE's visible-input console can display what you type.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

Tests use fabricated inputs and mocked HTTP responses. They check scoring boundaries, hash-prefix requests, matching counts, padding entries, and network error handling without contacting HIBP.

## Skills demonstrated

- Python functions, regular expressions, and command-line input
- REST API requests, timeouts, and HTTP error handling
- Local hashing and privacy-conscious API integration
- Unit testing with mocked network responses
- Explaining the limits of security estimates

## Future improvements

- Use a guessability estimator such as `zxcvbn`
- Add an offline-only option
- Improve Unicode handling and malformed-response handling
