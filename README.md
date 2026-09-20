# Phishing URL Detector

![CI](https://github.com/SarveshManulal/phishing-url-detector/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)

A lightweight, explainable Python tool that analyzes URLs and classifies them as **LIKELY SAFE**, **SUSPICIOUS**, or **PHISHING**. It uses transparent, weighted heuristics and reports the signals that contributed to each score instead of returning an opaque prediction.

> **Educational use only.** This project is intended for learning and portfolio use. It is not a replacement for commercial web-security products, browser protections, reputation feeds, or Google Safe Browsing.

## Features

The detector examines URL structure without fetching the target page. Signals include:

- Raw, decimal-encoded, and hexadecimal-encoded IP addresses in place of domains
- Missing HTTPS, non-standard ports, and suspicious `//` path redirects
- Long URLs, many subdomains, excessive hyphens, high digit ratios, and high hostname entropy
- Suspicious words such as `login`, `verify`, `account`, `secure`, `password`, and `billing`
- Brand impersonation, such as `paypal-secure.evil-site.example`
- `@` symbols that can obscure the actual destination
- Punycode (`xn--`) hostnames and known URL shorteners
- Frequently abused top-level domains
- Percent-encoded characters and other obfuscation signals
- Optional domain-age scoring through WHOIS lookup

Scores are capped at 100 and mapped to verdicts using these thresholds:

| Score | Verdict |
| ---: | --- |
| 0–29 | LIKELY SAFE |
| 30–59 | SUSPICIOUS |
| 60–100 | PHISHING |

## Requirements

- Python 3.9 or newer
- No third-party packages for core URL analysis
- Optional dependencies in `requirements.txt` for WHOIS lookup, the ML experiment, and testing

## Installation

```bash
git clone https://github.com/SarveshManulal/phishing-url-detector.git
cd phishing-url-detector

# Install development and optional dependencies
python -m pip install -r requirements.txt
```

If you only need the core detector, you can run it with the Python standard library alone.

## Command-line usage

Analyze one or more URLs:

```bash
python -m phishing_detector \
  https://www.google.com \
  http://secure-paypal-login.verify-account.tk/update
```

Read URLs from a text file. Blank lines and lines beginning with `#` are ignored:

```bash
python -m phishing_detector --file urls.txt
```

Include an optional domain-age lookup. This requires `python-whois` and network access:

```bash
python -m phishing_detector --whois https://example.com
```

Emit machine-readable JSON:

```bash
python -m phishing_detector --json http://paypal-secure.evil-site.tk
```

Disable ANSI colors in terminal output:

```bash
python -m phishing_detector --no-color https://example.com
```

### Example output

```text
https://www.google.com
  verdict: LIKELY SAFE   score: 0/100

http://secure-paypal-login.verify-account.tk/update
  verdict: PHISHING   score: 93/100
    +10: does not use HTTPS
    +8: 3 hyphens in hostname
    +20: suspicious keywords in hostname: login, verify, account, secure
    +5: suspicious keywords in path: update
    +25: mentions 'paypal' but the domain belongs to 'verify-account.tk'
    +15: TLD is commonly abused
    +10: hostname looks randomly generated (high entropy)
```

## Python API

The package can also be used directly from Python:

```python
from phishing_detector import analyze

result = analyze("http://apple.com@login-verify.example-secure.xyz/")

print(result.verdict)  # PHISHING
print(result.score)    # weighted score from 0 to 100
for reason in result.reasons:
    print(reason)
```

Each result contains the original URL, verdict, score, human-readable reasons, and extracted features. Use `result.as_dict()` when a JSON-serializable dictionary is more convenient.

## How it works

```text
URL ──► features.py ──► detector.py ──► verdict + reasons
        (pure parsing)   (weighted rules)
             ▲
             └── whois_lookup.py (optional domain age)
```

- `features.py` normalizes the input and extracts URL, hostname, path, encoding, domain, and entropy features. The normal feature path is deterministic and does not make network requests.
- `detector.py` applies weighted rules, adds a reason for every triggered signal, caps the score at 100, and selects the verdict.
- `whois_lookup.py` is used only when `--whois` is supplied. Domains younger than 30 days add 30 points; domains younger than 180 days add 15 points.

## Optional machine-learning experiment

The repository includes a small Random Forest experiment that reuses the non-network URL features:

```bash
python -m ml.train --data data/sample_urls.csv --out model.joblib
```

The CSV must contain `url` and `label` columns, where `1` means phishing and `0` means legitimate. The included dataset is a tiny smoke-test fixture, **not a benchmark**. Its metrics should not be treated as evidence of production performance. For meaningful evaluation, use a larger, independently collected dataset, a held-out test set, and report precision, recall, and F1.

## Project structure

```text
phishing-url-detector/
├── phishing_detector/
│   ├── cli.py              Command-line interface
│   ├── detector.py         Weighted scoring and verdicts
│   ├── features.py         URL feature extraction
│   └── whois_lookup.py     Optional domain-age lookup
├── ml/
│   └── train.py             Optional Random Forest experiment
├── data/
│   └── sample_urls.csv     Small demonstration dataset
├── tests/
│   └── test_detector.py    Unit tests for parsing and scoring
├── .github/workflows/
│   └── ci.yml              GitHub Actions test matrix
├── requirements.txt        Optional and development dependencies
└── LICENSE                 MIT license
```

## Testing

Run the test suite from the repository root:

```bash
pytest
```

The GitHub Actions workflow runs the tests on Python 3.9, 3.11, and 3.12.

## Limitations and responsible use

- Heuristics can produce both false positives and false negatives. A legitimate URL containing words such as `secure` or `account` may be flagged, while a carefully crafted phishing URL may score low.
- The detector analyzes the URL string only. It does not fetch pages, inspect HTML or JavaScript, follow redirects, or consult reputation services.
- Registered-domain parsing is intentionally approximate and does not use the full Public Suffix List.
- WHOIS information may be unavailable, privacy-redacted, or inconsistent; in those cases, domain-age scoring is skipped.
- A verdict is an investigation aid, not a guarantee that a URL is safe or malicious. Do not open suspicious links merely to test them.

## Roadmap

- [ ] Use the Public Suffix List for exact registered-domain parsing
- [ ] Add reputation checks through services such as PhishTank, OpenPhish, or Google Safe Browsing
- [ ] Follow redirects and expand shortened URLs safely
- [ ] Add Unicode confusable-character detection
- [ ] Provide a small Flask/FastAPI web interface and browser-extension prototype

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
