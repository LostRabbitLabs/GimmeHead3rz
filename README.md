[![N|Solid](https://www.lostrabbitlabs.com/files/pics/LRLlogo-TM.png)](https://www.lostrabbitlabs.com)

# --- GimmeHead3rz ---
GimmeHead3rz is an up-to-date customizable HTTP/HTTPS header analyzer that evaluates security flags on cookies and looks for missing security headers and then categorizes found headers into the following categories:
- Common Headers
- Anomalous Headers
- Security Headers

## Features

- Customizable common-headers.txt and security-headers.txt files for your use-cases
- Single target and multi-target analysis
- Analyzes cookies and associated flags
- Supports different HTTP verbs (GET/OPTIONS/HEAD/POST/PUT/PATCH/DELETE/ETC...)
- Supports customizable cookies to the request(s) for authenticated analysis
- Supports customizable headers (both name and value) to the request(s)
- Supports a customizable Host header
- Supports a customizable User-Agent header
- Supports customizable body content for request(s)
- Supports uploading a specified file as body for request(s)
- Supports ignoring bad certificates on HTTPS requests (through the --insecure flag)
- Supports following redirects on all requests (through the --redirects flag)
- Supports a specified timeout period for request(s)

## Installation

GimmeHead3rz requires [Python3](https://www.python.org/downloads/) to run.

Clone the repository and pip install dependencies.

```sh
git clone https://gitlab.com/lost-rabbit-labs/gimmehead3rz.git
cd gimmehead3rz
pip install -r requirements.txt
```

## Sample Commands

- `./gimmehead3rz.py https://example.com -r` - Sets follow redirection to TRUE for the request.
- `./gimmehead3rz.py https://example.com/dashboard -c "mainCookie:Nelson-Cook" "otherCookie=CoconutHead"` - Sets the cookie to use for the request.
- `./gimmehead3rz.py https://example.com -ch "Header1:letmein" "Header2:justkidding"` - Add multiple headers to your request.
- `./gimmehead3rz.py https://example.com -v POST -d "TESTING!"` - Uploads the content via POST verb to the target.
- `./gimmehead3rz.py https://example.com -v POST -df content.json` - Uploads JSON file via POST verb to the target 
- `./gimmehead3rz.py -t targets.txt -h localhost -i -t 15` - Analyzes all targets with a custom Host header of localhost, ignores bad certs, and has a timeout time of 15 seconds for all requests.
- `./gimmehead3rz.py -t targets.txt -ua "Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/10.0"` - Analyzes all targets with a custom User-Agent for all requests.

## Development

Any bugs to report or ideas to make it better?

Let us know in the comments or at a con.

## License

MIT License

