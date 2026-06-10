# obfu.py - Payload Obfuscation Script

A Python 3 script for encoding/obfuscating payloads into various character encodings.

## Usage

```
python3 obfu.py -s '<payload>' -e <encoding> [-ueo] [-udi]
```

## Arguments

- `-s/--str` - String to obfuscate (required)
- `-e/--enc` - Encoding type (required, e.g., ibm037, utf-16)
- `-ueo` - URL Encode Output (optional)
- `-udi` - URL Decode Input (optional)

## Example

```bash
python3 obfu.py -s 'param=<svg/onload=prompt()//' -e ibm037 -ueo
```

## Supported Encodings

All encodings supported by Python's codec system, including:
- IBM037, IBM500, cp875, IBM1026, IBM273 (EBCDIC variants)
- UTF-16, UTF-16BE, UTF-32, UTF-32BE
- cp850, cp852, cp855, cp857, cp860, cp861, cp862, cp863, cp864, cp865, cp866, cp869
- ISO-8859-1 through ISO-8859-16
- And many more
