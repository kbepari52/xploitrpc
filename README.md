# XML-RPC Testing Tool Kit

```
╔════════════════════════════════════════════════════╗
║            XML-RPC Testing Tool Kit               ║
║             Explore • Attack • Exploit            ║
╠════════════════════════════════════════════════════╣
║  __  ______  _       _ _   ____  ____   ____      ║
║  \ \/ /  _ \| | ___ (_) |_|  _ \|  _ \ / ___|     ║
║   \  /| |_) | |/ _ \| | __| |_) | |_) | |         ║
║   /  \|  __/| | (_) | | |_|  _ <|  __/| |___      ║
║  /_/\_\_|   |_|\___/|_|\__|_| \_\_|    \____|     ║
╠════════════════════════════════════════════════════╣
║  Developed by: Krishanu Bepari                     ║
║  GitHub: github.com/kbepari52                      ║
╚════════════════════════════════════════════════════╝
```

## Overview

**XML-RPC Testing Tool Kit** (`xploitrpc.py`) is a professional toolkit for exploring, attacking, and exploiting XML-RPC endpoints. It is designed for penetration testers, security researchers, and developers to interact with and test XML-RPC APIs, especially those used by platforms like WordPress.

## Features

- Animated hacker-style banner
- List all available XML-RPC methods
- View method signatures and help (if supported)
- Dynamic method invocation with argument prompts
- WordPress XML-RPC bruteforce (username/password or file-based)
- Authenticated action testing
- User-friendly, menu-driven interface
- Error handling for real-world scenarios

## Usage

1. **Clone this repository:**
   ```bash
   git clone https://github.com/kbepari52/xmlrpc-toolkit.git
   cd xmlrpc-toolkit
   ```

2. **Install dependencies:**
   - Python 3.x is required (tested on Python 3.6+)
   - No external dependencies are required; only Python standard library modules are used (`xmlrpc.client`, `sys`, `time`).

3. **Run the tool:**
   ```bash
   python xploitrpc.py
   ```

4. **Follow the prompts:**
   - Enter the XML-RPC endpoint URL.
   - Choose whether you have credentials.
   - Use the menu to list methods, ping, bruteforce, test authenticated actions, or call any method dynamically.

5. **Dynamic Method Call:**
   - After listing methods, select "Call Any Method (Dynamic)".
   - Enter the method name as shown in the list.
   - The tool will display required arguments and prompt you to proceed or go back.
   - Enter arguments as prompted.

## Example

```
Enter XML-RPC endpoint URL: http://example.com/xmlrpc.php
Do you have valid credentials? (y/n): y
Enter username: admin
Enter password: *****
...
```

## Dependencies

- Python 3.x (standard library only)
  - `xmlrpc.client`
  - `sys`
  - `time`

No third-party packages are required.

## Disclaimer

This tool is for educational and authorized penetration testing purposes only. Do not use it on systems you do not own or have explicit permission to test.

---

**Developed by:** Krishanu Bepari  
**GitHub:** [github.com/kbepari52](https://github.com/kbepari52)
