#!/usr/bin/env python3
import requests
from time import gmtime, strftime, localtime
import argparse
from re import sub
from colorama import Fore, Back, Style
requests.packages.urllib3.disable_warnings()

def analyzeHeaders(args):
    reqHeaders = {}
    uaHeader = {'User-Agent': args.user_agent} if args.user_agent else {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0'}
    reqHeaders.update(uaHeader)
    hostHeader = {'Host': args.hostname} if args.hostname else None

    if args.hostname:
        reqHeaders.update(hostHeader)

    if args.custom_headers:
        for h in args.custom_headers:
            headerName, headerVal = h.split(':', 1)
            tmp_dict = {headerName: headerVal}
            reqHeaders.update(tmp_dict)

    customCookie = {} if args.cookie else None
    if args.cookie:
        for c in args.cookie:
            cookieName, cookieVal = c.split(':', 1)
            cookie_dict = {cookieName: cookieVal}
            customCookie.update(cookie_dict)

    httpsVerify = False if args.insecure else True
    redirects = True if args.redirects else False
    displayContent = True if args.display_content else None
    dataContents = None
    if args.data:
        dataContents = args.data if args.data else None
    if args.data_file:
        dataContents = open(args.data_file) if args.data_file else None
    if args.url:
        print(Style.DIM + Fore.GREEN + 'Starting GimmeHead3rz against: ' + Fore.YELLOW + args.url + Style.RESET_ALL)
        try:
            r = requests.request(args.verb, args.url, cookies=customCookie, headers=reqHeaders, data=dataContents, allow_redirects=redirects, timeout=args.timeout, verify=httpsVerify)
        except Exception as e:
            print(e)
            return
        if redirects:
            print(Style.DIM + Fore.GREEN + 'Redirection enabled, request is following: ' + Fore.YELLOW + r.url + Style.RESET_ALL)
        if not redirects and r.next:
            print(Style.DIM + Fore.GREEN + 'Request is trying to redirect to: ' + Fore.YELLOW + r.next.url + Style.RESET_ALL)
        if not httpsVerify:
            print(Style.DIM + Fore.GREEN + 'Insecure flag set, ignoring cert issues.')

        if args.hostname:
            print(Style.DIM + Fore.GREEN + 'Using custom Host header: ' + Fore.YELLOW + args.hostname + Style.RESET_ALL)
        if args.custom_headers:
            for h in args.custom_headers:
                headerName, headerVal = h.split(':', 1)
                print(Style.DIM + Fore.GREEN + 'Using custom header: ' + Fore.YELLOW + headerName + ': ' + headerVal + Style.RESET_ALL)
        if args.user_agent:
            print(Style.DIM + Fore.GREEN + 'Using custom user-agent: ' + Fore.YELLOW + args.user_agent + Style.RESET_ALL)
        if args.cookie:
            for c in args.cookie:
                cookieName, cookieVal = c.split(':', 1)
                print(Style.DIM + Fore.GREEN + 'Using custom cookie(s): ' + Fore.YELLOW + cookieName + '=' + cookieVal + Style.RESET_ALL)
        if args.verb and args.verb != 'GET':
            print(Style.DIM + Fore.GREEN + 'Using HTTP/HTTPS verb: ' + Fore.YELLOW + args.verb + Style.RESET_ALL)
        if args.data:
            print(Style.DIM + Fore.GREEN + 'Data sent in the request(s): ' + Fore.YELLOW + dataContents + Style.RESET_ALL)
        if args.data_file:
            print(Style.DIM + Fore.GREEN + 'Data file in the request(s): ' + Fore.YELLOW + args.data_file + Style.RESET_ALL)

        headerKeys = list(r.headers.keys())
        print(Style.DIM + Fore.GREEN + 'Total Headers Found: ' + Fore.YELLOW + str(len(headerKeys)) + Style.RESET_ALL)
        headerVals = list(r.headers.values())
        securityHeadersFound = []
        securityHeadersNames = []
        commonHeadersFound = []
        anomHeadersFound = []
        cookieVal = ''

        for h,v in zip(headerKeys,headerVals):
            found = False
            security = open('security-headers.txt', encoding='utf-8')
            common = open('common-headers.txt', encoding='utf-8')

            if h.lower() in 'set-cookie':
                commonHeadersFound.append('Set-Cookie: ' + v[0:30] + '...')

            for line in security:
                if h.lower() in line.lower() and 'set-cookie' not in h.lower() and h.lower() != 'content-type':
                    found = True
                    securityHeadersNames.append(h.lower())
                    securityHeadersFound.append(camelCase(h.rstrip()) + ': ' + v)
                    break

            for line in common:
                if h.lower() in line.lower() and h.lower() not in securityHeadersNames:
                    found = True
                    if h.lower() not in 'set-cookie':
                        commonHeadersFound.append(camelCase(h.rstrip()) + ': ' + v)
                        break

            if not found and h.lower() not in 'set-cookie':
                anomHeadersFound.append(h.rstrip() + ': ' + v)

            security.close()
            common.close()

        printHeaderInfo(commonHeadersFound, anomHeadersFound, securityHeadersFound, securityHeadersNames, r, args.url, displayContent)

        print(Style.DIM + Fore.GREEN + 'Finished Analyzing Headers at: ' + Fore.YELLOW + strftime("%a, %d %b %Y %H:%M:%S", localtime()) + Style.RESET_ALL)

    elif args.targets:
        targets = open(args.targets, "r")
        for t in targets:
            print(Style.DIM + Fore.GREEN + 'Starting GimmeHead3rz against: ' + Fore.YELLOW + t.rstrip() + Style.RESET_ALL)
            try:
                r = requests.request(args.verb, t.rstrip(), cookies=customCookie, headers=reqHeaders, data=dataContents, allow_redirects=redirects, timeout=args.timeout, verify=httpsVerify)
            except Exception as e:
                print(e)
                continue

            if redirects:
                print(Style.DIM + Fore.GREEN + 'Redirection enabled, request is following: ' + Fore.YELLOW + r.url + Style.RESET_ALL)
            if not redirects and r.next:
                print(Style.DIM + Fore.GREEN + 'Request trying to redirect to (not following): ' + Fore.YELLOW + r.next.url + Style.RESET_ALL)
            if args.hostname:
                print(Style.DIM + Fore.GREEN + 'Using custom Host header: ' + Fore.YELLOW + args.hostname + Style.RESET_ALL)
            if args.custom_headers:
                for h in args.custom_headers:
                    headerName, headerVal = h.split(':', 1)
                    print(Style.DIM + Fore.GREEN + 'Using custom header: ' + Fore.YELLOW + headerName + ': ' + headerVal + Style.RESET_ALL)
            if args.user_agent:
                print(Style.DIM + Fore.GREEN + 'Using custom user-agent: ' + Fore.YELLOW + args.user_agent + Style.RESET_ALL)
            if args.cookie:
                for c in args.cookie:
                    cookieName, cookieVal = c.split(':', 1)
                    print(Style.DIM + Fore.GREEN + 'Using custom cookie(s): ' + Fore.YELLOW + cookieName + '=' + cookieVal + Style.RESET_ALL)
            if args.verb and args.verb != 'GET':
                print(Style.DIM + Fore.GREEN + 'Using HTTP/HTTPS verb: ' + Fore.YELLOW + args.verb + Style.RESET_ALL)
            if args.data:
                print(Style.DIM + Fore.GREEN + 'Data sent in the request(s): ' + Fore.YELLOW + dataContents + Style.RESET_ALL)
            if args.data_file:
                print(Style.DIM + Fore.GREEN + 'Data file in the request(s): ' + Fore.YELLOW + args.data_file + Style.RESET_ALL)

            headerKeys = list(r.headers.keys())
            print(Style.DIM + Fore.GREEN + 'Total Headers Found: ' + Fore.YELLOW + str(len(headerKeys)) + Style.RESET_ALL)
            headerVals = list(r.headers.values())
            securityHeadersFound = []
            securityHeadersNames = []
            commonHeadersFound = []
            anomHeadersFound = []
            cookieVal = ''

            for h,v in zip(headerKeys,headerVals):
                found = False
                security = open('security-headers.txt', encoding='utf-8')
                common = open('common-headers.txt', encoding='utf-8')

                if h.lower() in 'set-cookie':
                    commonHeadersFound.append('Set-Cookie: ' + v[0:30] + '...')

                for line in security:
                    if h.lower() in line.lower() and 'set-cookie' not in h.lower() and h.lower() != 'content-ype':
                        found = True
                        securityHeadersNames.append(h.lower())
                        securityHeadersFound.append(camelCase(h.rstrip()) + ': ' + v)
                        break

                for line in common:
                    if h.lower() in line.lower() and h.lower() not in securityHeadersNames:
                        found = True
                        if h.lower() not in 'set-cookie':
                            commonHeadersFound.append(camelCase(h.rstrip()) + ': ' + v)
                            break

                if not found and h.lower() not in 'set-cookie':
                    anomHeadersFound.append(h.rstrip() + ': ' + v)

                security.close()
                common.close()

            printHeaderInfo(commonHeadersFound, anomHeadersFound, securityHeadersFound, securityHeadersNames, r, t, displayContent)

        targets.close()
        print(Style.DIM + Fore.GREEN + 'Finished Analyzing Headers at: ' + Fore.YELLOW + strftime("%a, %d %b %Y %H:%M:%S", localtime()) + Style.RESET_ALL)
    else:
        print('uh oh... Something went wrong :/')

def printHeaderInfo(commonHeadersFound, anomHeadersFound, securityHeadersFound, securityHeadersNames, r, target, displayContent):
    if commonHeadersFound:
        print('\n|--- COMMON HEADERS DETECTED ---|' + Style.RESET_ALL)
        for c in range(0, len(commonHeadersFound), 1):
            print(Style.DIM + Fore.CYAN + '|- ' + commonHeadersFound[c] + Style.RESET_ALL)

    if anomHeadersFound:
        print('\n|--- ANOMALOUS HEADERS DETECTED ---|' + Style.RESET_ALL)
        for a in range(0, len(anomHeadersFound), 1):
            print(Fore.MAGENTA + '|- ' + anomHeadersFound[a] + Style.RESET_ALL)

    if securityHeadersFound:
        print('\n|--- SECURITY HEADERS DETECTED ---|' + Style.RESET_ALL)
        for s in range(0, len(securityHeadersFound), 1):
            print(Style.DIM + Fore.GREEN + '|- ' + securityHeadersFound[s] + Style.RESET_ALL)

    missingSecurityHeaders = getMissingHeaders(securityHeadersNames)
    if missingSecurityHeaders:
        print('\n|--- SECURITY HEADERS MISSING ---|' + Style.RESET_ALL)
        for m in range(0, len(missingSecurityHeaders), 1):
            print(Fore.RED + '|- ' + camelCase(missingSecurityHeaders[m]) + Style.RESET_ALL)

    printCookies(r.cookies)
    if displayContent:
        printContent(r.text)

    print('\n' + Style.DIM + Fore.GREEN + 'Finished Analyzing Headers for: ' + Fore.YELLOW + target.rstrip())
    print('----------------------------------------------------------' + Style.RESET_ALL)

def getMissingHeaders(securityHeadersNames):
    securityHeaders = []
    security = open('security-headers.txt', encoding='utf-8')
    for line in security:
        securityHeaders.append(line.lower().rstrip())
    securityHeadersDifference = [header for header in securityHeaders if header not in securityHeadersNames]
    return securityHeadersDifference

def camelCase(s):
    s = sub(r"(_|-)+", "-", s).title().replace(" ", "")
    return ''.join([s[0].upper(), s[1:]])

def printContent(content):
    print('\n|--- Web Page Content ---|')
    print(Style.DIM + Fore.CYAN + content + Style.RESET_ALL)

def printCookies(cookies):
    print('\n|--- Analyzing C00kies ---|' + Style.RESET_ALL)
    if cookies:
        for c in cookies:
            if c.value is None:
                print(Fore.CYAN + 'Cookie name: \'' + c.name + '\' does not contain any values.' + Style.RESET_ALL)
                break
            print(Style.BRIGHT + Fore.BLACK + '|--- C00kie: ' + c.name + '= ' + c.value + Style.RESET_ALL)
            if not c.secure:
                print(Fore.RED + '|---- Secure Flag Missing   - (Not OK)' + Style.RESET_ALL)
            if c.secure:
                print(Style.DIM + Fore.GREEN + '|---- Secure Flag Set!      - (GOOD)' + Style.RESET_ALL)
            if not c.get_nonstandard_attr('HttpOnly'):
                print(Fore.RED + '|---- HTTPOnly Flag Missing - (Not OK, unless JS needs to access it!)' + Style.RESET_ALL)
            if c.get_nonstandard_attr('HttpOnly'):
                print(Style.DIM + Fore.GREEN + '|---- HTTPOnly Flag Set!     - (GOOD)' + Style.RESET_ALL)
            if not c.expires:
                print(Fore.CYAN + '|---- Expires Flag Missing  - (Informational)' + Style.RESET_ALL)
            if c.expires:
                print(Fore.CYAN + '|---- Expires Flag Set!     - (Informational)' + Style.RESET_ALL)
            if not c.get_nonstandard_attr('SameSite'):
                print(Fore.CYAN + '|---- SameSite Flag Missing - (Informational)' + Style.RESET_ALL)
            if c.get_nonstandard_attr('SameSite'):
                print(Fore.CYAN + '|---- SameSite Flag Set!    - (Informational)' + Style.RESET_ALL)
            if not c.get_nonstandard_attr('Priority'):
                print(Fore.CYAN + '|---- Priority Flag Missing - (Informational)' + Style.RESET_ALL)
            if c.get_nonstandard_attr('Priority'):
                print(Fore.CYAN + '|---- Priority Flag Set!    - (Informational)' + Style.RESET_ALL)
            if c.domain:
                print(Fore.CYAN + '|---- Associated Domains    - ' + c.domain + Style.RESET_ALL)
            if not c.domain:
                print(Fore.CYAN + '|---- No Domains Associated?' + Style.RESET_ALL)
            print('')
    else:
        print(Style.BRIGHT + Fore.BLACK + 'No Cookies Found ;\'(' + Style.RESET_ALL)

def printArt():
    img = """

  ....                          ....
 .:cc::;'..                  ..',,..
  .,:ccllc:;,.           .';:cllc;.
    'cllcc:c::,.       .,cllcc:,.
     .,clc:::::,.     .,::::;..
        ..',:::;,'''',,::::,.
           .:ccccccccccccc::,'..
        .':cccccccllcccc::::::::,.
      .,clcccccllc:::ccllc::::::c:'
     .:ollccccc:'. .. .'coc:;::::::,.
    .;llllcccclc.       ,oo:;;::::::'
    'lllllcc::cl;.      .cl:::::::::;.
   .:olllccc:::::;,',,;;;::::;::ccc:;.
   .coolccccccc::;;;,,,;;;:clllc::c:;.
   .:olllcccccccccc:c::::::ldddol;,;c'
    ,:::::::;::::cclllllllcclllll:;::.
   .::;;;;,,;:::cloooooooodddollllc;.
   'c:;;,,;:cllolooooodddddddddoolc.
   ,::;,,,:llllllooooooooooooollc:'
  ':;,''',::clllloolooolllllcc::,.
 .''.......',;;;:cclccccc:::;,'.      ...
 ....         ....'',,,,'''..    .......
                 ..       ...........
                 .,'....',,,....
               .,,,''''''...
           .',:::,.....
         .',;;;,.
      .',;;,..
    ..';;'..
   .......
 ......
..... """
    print(Style.DIM + Fore.WHITE + img + Style.RESET_ALL)
    print(Style.BRIGHT + Fore.BLUE + "::::::::::::::::::::::::::::::::::::::::::::::" + Style.RESET_ALL)
    print(Style.BRIGHT + Fore.BLUE + "        :::    Lost Rabbit Labs    :::        " + Style.RESET_ALL)
    print(Style.BRIGHT + Fore.BLUE + "        ::: ---- GimmeHead3rz ---- :::        " + Style.RESET_ALL)
    print(Style.BRIGHT + Fore.BLUE + "        ::: -------- v1.0 -------- :::        " + Style.RESET_ALL)
    print(Style.BRIGHT + Fore.BLUE + "::::::::::::::::::::::::::::::::::::::::::::::" + Style.RESET_ALL)
    print('')

formatter = lambda prog: argparse.HelpFormatter(prog, indent_increment=7, max_help_position=25, width=130)
parser = argparse.ArgumentParser(prog='gimmehead3rz.py', description='Analyze HTTP Headers by using a single URL or a targets file followed by additional arguments. Example command usage below.  ./gimmiehead3rz.py https://example.com -dc -r -to 30', formatter_class=formatter)

targetsGroup = parser.add_mutually_exclusive_group()
targetsGroup.add_argument('url', nargs='?', action='store', help='URL of a single HTTP or HTTPS service to analyze.', metavar='URL')
targetsGroup.add_argument('-t', '--targets', nargs='?', action='store', help='Line seperated file of URLs to analyze.', metavar='targets.txt')

parser.add_argument('-c','--cookie', nargs='+', action='store', help='Customizable cookie for the analysis. Example: -c "BestCookie:Nelson-Cook" "Cookie2:Value2"', metavar='"COOKIE_NAME:COOKIE_VAL"')
parser.add_argument('-ch', '--custom-headers', nargs='+', action='store', help='Customizable HTTP/HTTPS headers to use in the request(s). Example: -ch "Header1:Yes" "Header2:No"', metavar='"H1:V1" "H2:V2"')
parser.add_argument('-d', '--data', nargs='?', action='store', help='Send data in your PUT/POST request(s). Example: -d \'{ "Key": "Val" }\'', metavar='BODY_STR')
parser.add_argument('-dc', '--display-content', nargs='?', const=True, action='store', help='FLAG ONLY. Display content from request(s). Example: URL -dc', metavar='FLAG_ONLY')
parser.add_argument('-df', '--data-file', nargs='?', action='store', help='Specify file of data to send in your request. Example: -df content.json', metavar='FILE_NAME')
parser.add_argument('-host', '--hostname', action='store', help='Customizable host header for the analysis. Example: -host 127.0.0.1', metavar='HOSTHEADER_VAL')
parser.add_argument('-i','--insecure', nargs='?', const=True, action='store', help='FLAG ONLY. Ignore certificate errors for the HTTPS related request(s). Default is True. Example: URL -i', metavar='FLAG_ONLY')
parser.add_argument('-r', '--redirects', nargs='?', const=True, help='FLAG ONLY. Use this option to follow redirects for all target(s). Default is False. Example: URL -r', metavar='FLAG_ONLY')
parser.add_argument('-to', '--timeout',  action='store', type=int, default=12, help='Sets the timeout length in seconds. Default is 12 seconds. Example: -to 30', metavar='INT')
parser.add_argument('-ua','--user-agent', action='store', help='Customizable user-agent to use in the request(s). Example: -ua "Curl/7.77.0"', metavar='"USER_AGENT_STR"')
parser.add_argument('-v', '--verb', action='store', default='GET', help='Set the HTTP verb to use for the request. Default is \'GET\'. Example: -v POST', metavar='POST/PUT/OPTIONS/DELETE/ETC..')
args = parser.parse_args()

if args.url or args.targets:
    printArt()
    analyzeHeaders(args)
else:
    parser.print_help()

