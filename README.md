<table>
    <tr style="text-align: left; border: 0px">
        <th style="height: auto; width: 160px; padding-top: 55px">
            <img src="https://www.lostrabbitlabs.com/files/pics/logos/LRL-MainLogo-WBG.jpg" width="210">
        </th>
        <th>
            <h1> --- GimmeHead3rz v1.0 --- </h1>
            <p><strong>GimmeHead3rz</strong> is an up-to-date customizable HTTP/HTTPS header analyzer that evaluates security flags on cookies and looks for missing security headers and then categorizes found headers into the Common Headers, Anomalous Headers, Security Headers categories.</p>
        </th>
    </tr>
</table>

## Contributors

Original concept and code by <a href="https://gitlab.com/Murmaid3r">

<strong>@Murmaid3r</strong></a>

<a href="https://gitlab.com/Murmaid3r"><img style="border-radius: 50%" src="https://gitlab.com/uploads/-/system/user/avatar/4966171/avatar.png?width=192" width="100"></a>

## Features

- Analyze cookies, associated flags, and response content for single and multi-targets.
- Supports customizable cookies, headers, Hosts, User-Agents, common-headers.txt, security-headers.txt, and request body content.
- Supports scan customization through usage of flags like --insecure, --redirects, --verb, and others.
- Supports uploading a specified file as the body for request(s)

## Installation

<strong>GimmeHead3rz</strong> requires [Python3](https://www.python.org/downloads/) to run.

Clone the repository and pip install dependencies.

```sh
git clone https://gitlab.com/lost-rabbit-labs/gimmehead3rz.git
cd gimmehead3rz
pip install -r requirements.txt
```

## Sample Commands

<strong>Sets follow redirection to TRUE for the request</strong>:<br>
`./gimmehead3rz.py https://example.com -r`

<strong>Sets the cookie to use for the request:</strong><br>
`./gimmehead3rz.py https://example.com/dashboard -c "mainCookie:Nelson-Cook" "otherCookie=CoconutHead"`

<strong>Add multiple headers to your request:</strong><br>
`./gimmehead3rz.py https://example.com -ch "Header1:letmein" "Header2:justkidding"`

<strong>Uploads the content via POST verb to the target:</strong><br>
`./gimmehead3rz.py https://example.com -v POST -d "TESTING!"`

<strong>Uploads JSON file via POST verb to the target:</strong><br>
`./gimmehead3rz.py https://example.com -v POST -df content.json`

<strong>Analyzes all targets with a custom Host header of localhost, ignores bad certs, displays content received, and has a timeout time of 15 seconds for all requests:</strong><br>
`./gimmehead3rz.py -t targets.txt -h localhost -i -dc -t 15`

<strong>Analyzes all targets with a custom User-Agent for all requests</strong><br>
`./gimmehead3rz.py -t targets.txt -ua "Mozilla/5.0 (X11; Linux x86_64; rv:10.0) Gecko/20100101 Firefox/10.0"`

## License

MIT License