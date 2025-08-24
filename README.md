# XML-RPC Testing Tool Kit

```
╔════════════════════════════════════════════════════╗
║            XML-RPC Testing Tool Kit                ║
║             Explore • Attack • Exploit             ║
╠════════════════════════════════════════════════════╣
║  __  ______  _       _ _   ____  ____   ____       ║
║  \ \/ /  _ \| | ___ (_) |_|  _ \|  _ \ / ___|      ║
║   \  /| |_) | |/ _ \| | __| |_) | |_) | |          ║
║   /  \|  __/| | (_) | | |_|  _ <|  __/| |___       ║
║  /_/\_\_|   |_|\___/|_|\__|_| \_\_|    \____|      ║
╠════════════════════════════════════════════════════╣
║  Developed by: Krishanu Bepari                     ║
║  GitHub: github.com/kbepari52                      ║
╚════════════════════════════════════════════════════╝
```

## Overview

**XML-RPC Testing Tool Kit** (`xploitrpc.py`) is a professional toolkit for exploring, attacking, and exploiting XML-RPC endpoints. It is designed for penetration testers, security researchers, and developers to interact with and test XML-RPC APIs, especially those used by platforms like WordPress.

## Features

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

This tool allows you to test XML-RPC endpoints both with valid credentials (authenticated) and without credentials (unauthenticated), depending on your needs.

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

If any of these dependencies are not available in your Python environment, you can install them using `pip` (though they are included by default in standard Python 3.x installations):

```bash
pip install xmlrpc
```

## Disclaimer

This tool is intended for educational purposes and authorized penetration testing only. Use it responsibly and only on systems you own or have explicit, written permission to test. The author assumes no liability for any misuse or damage caused by this tool. By using this toolkit, you agree to comply with all applicable laws and regulations.

## License

This project is licensed under the MIT License.

```
MIT License

Copyright (c) 2024 Krishanu Bepari

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

**Developed by:** Krishanu Bepari  
**GitHub:** [github.com/kbepari52](https://github.com/kbepari52)
