# Memory Forensics Kit

> RAM Dump Analysis & Malware Detection Toolkit

![Python](https://img.shields.io/badge/Python-3.10+-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Status](https://img.shields.io/badge/Status-Active-red)

## Overview

A comprehensive memory forensics toolkit for analyzing RAM dumps, detecting malware artifacts, extracting credentials, and investigating live system memory during incident response.

## Features

- Volatility3 plugin integration
- Process injection detection (hollowing, DLL injection)
- Credential extraction from LSASS
- Network connection & socket enumeration
- Malware artifact hunting
- Timeline generation & reporting

## Quick Start

```bash
git clone https://github.com/Youssefzdb/memory-forensics-kit
cd memory-forensics-kit
pip install -r requirements.txt
python analyze.py --dump memory.dmp --profile Win10x64 --all
```

## Legal Disclaimer

> For authorized incident response and forensic investigations only.

## Author

**Youssef Zeidi** | Red Team Specialist | [GitHub](https://github.com/Youssefzdb)
