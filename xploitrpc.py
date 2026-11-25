#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
xploitrpc.py - compatibility entry point.

The implementation now lives in the `xrpc` package. This shim keeps the
original `python xploitrpc.py ...` interface working unchanged.

Designed for authorized penetration testing and security research only.
Use it on systems you own or have explicit written permission to test.

Author : Krishanu Bepari (github.com/kbepari52)
Version: 2.0.0
License: MIT
"""

from xrpc.cli import main

if __name__ == "__main__":
    main()
