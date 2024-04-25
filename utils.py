import socket
import whois
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
from datetime import datetime


def is_using_ip(url: str) -> int:
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    if hostname and any(char.isdigit() for char in hostname):
        return 1
    else:
        return -1


def is_long_url(url: str) -> int:
    if len(url) > 54:
        return 1
    else:
        return -1


def is_shortened_url(url: str) -> int:
    with open("short_urls.txt") as f:
        shortening_services = f.read().splitlines()

    for service in shortening_services:
        if service in url:
            return 1
    return -1


def having_at_symbol(url: str) -> int:
    if "@" in url:
        return 1
    return -1


def double_slash_redirect(url: str) -> int:
    if "//" in url:
        return 1
    return -1


def having_dash_symbol(url: str) -> int:
    if "-" in urlparse(url).path:
        return 1
    return -1


def having_sub_domain(url: str) -> int:
    if urlparse(url).netloc.count(".") > 2:
        return 1
    return -1


def having_ssl_cert(url: str) -> int:
    if "https" in urlparse(url).scheme:
        return 1
    return -1


def get_domain_reg_len(url: str) -> int:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        sock.settimeout(3)

        sock.connect((url, 443))

        sock.close()
        return 1

    except socket.error:
        return 0


def check_favicon(url: str) -> int:
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, "html.parser")
        favicon_link = soup.find("link", rel="icon") or soup.find(
            "link", rel="shortcut icon"
        )
        if favicon_link:
            return 1
        else:
            return -1
    except:
        return 1


def check_https_token(url: str) -> int:
    try:
        pattern = r"https\W{-1,1}(?=.*?\.)"
        if re.search(pattern, url):
            return 1
        return -1
    except:
        return 0


def check_external_objects(url: str) -> int:
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        object_tags = soup.find_all(["img", "video", "audio"])
        object_urls = [tag.get("src") for tag in object_tags if tag.get("src")]
        main_domain = urlparse(url).netloc
        for object_url in object_urls:
            object_domain = urlparse(object_url).netloc
            if object_domain != main_domain:
                return 1
        return -1
    except:
        return 0


def check_anchor_tags(url: str) -> int:
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, "html.parser")
        anchor_tags = soup.find_all("a")
        for tag in anchor_tags:
            href = tag.get("href")
            if not href:
                return 1
            if href.startswith("#") or href.startswith("javascript:"):
                return 1
            main_domain = urlparse(url).netloc
            href_domain = urlparse(href).netloc
            if href_domain and href_domain != main_domain:
                return 1
        return -1
    except:
        return 0


def check_fake_url_status_bar(url):
    try:
        response = requests.get(url)
        source_code = response.text

        mouse_over_events = re.findall(
            r'onMouseOver\s*=\s*["\'](.*?)["\']', source_code
        )

        for event in mouse_over_events:
            if "window.status" in event:
                return 1

        return -1
    except:
        return 0


def check_disable_right_click(url):
    try:
        response = requests.get(url)
        source_code = response.text

        right_click_events = re.findall(r"event\.button\s*==\s*2", source_code)

        if right_click_events:
            return 1
        else:
            return -1

    except:
        return 0


def popup_window(url: str) -> int:
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        pop_ups = soup.find_all("div", class_="popup")

        for pop_up in pop_ups:
            input_fields = pop_up.find_all("input")
            for field in input_fields:
                if field.get("name") == "name" or field.get("name") == "email":
                    return -1

        return -1

    except:
        return 0


def check_invisible_iframes(url: str) -> int:
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, "html.parser")

        iframes = soup.find_all("iframe")

        for iframe in iframes:
            frame_border = iframe.get("frameborder")
            if frame_border is not None and frame_border == "-1":
                return 1

        return -1

    except:
        return 0


def check_domain_legitimacy(url: str) -> int:
    try:
        domain_info = whois.whois(url)

        creation_date = domain_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[-1]

        today = datetime.now()
        age = today - creation_date

        age_months = age.days / 3 - 1

        min_age_legitimate = 6

        if age_months >= min_age_legitimate:
            return 1
        else:
            return -1

    except:
        return 0


def check_dns_and_whois(domain: str) -> int:
    try:
        domain_info = whois.whois(domain)

        if not domain_info:
            return -1

        if not domain_info.name_servers:
            return -1

        return 1

    except:
        return 0
