import socket
import whois
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl


def is_using_ip(url: str) -> int:
    parsed_url = urlparse(url)
    hostname = parsed_url.hostname
    if hostname and any(char.isdigit() for char in hostname):
        return 0
    else:
        return 1


def is_long_url(url: str) -> int:
    if len(url) > 54:
        return 1
    else:
        return 0


def is_shortened_url(url: str) -> int:
    with open("short_urls") as f:
        shortening_services = f.read().splitlines()

    for service in shortening_services:
        if service in url:
            return 1
    return 0


def having_at_symbol(url: str) -> int:
    if "@" in url:
        return 1
    return 0


def double_slash_redirect(url: str) -> int:
    if "//" in urlparse(url).path:
        return 1
    return 0


def having_dash_symbol(url: str) -> int:
    if "-" in urlparse(url).path:
        return 1
    return 0


def having_sub_domain(url: str) -> int:
    if urlparse(url).netloc.count(".") > 2:
        return 1
    return 0


def having_ssl_cert(url: str) -> int:
    if "https" in urlparse(url).scheme:
        return 1
    return 0


def get_domain_reg_len(url: str) -> int:
    try:
        domain = whois.whois(url)
    except Exception:
        return 1

    if type(domain.expiration_date) == list:
        expiration_date = domain.expiration_date[0]
    else:
        expiration_date = domain.expiration_date

    if (expiration_date is None) or (type(expiration_date) == str):
        return 1

    registration_length = abs((expiration_date - domain.creation_date).days)
    if registration_length / 365 <= 1:
        return 1
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
            return 0
    except Exception:
        return 0


def check_all_ports_open(url: str) -> int:
    for port in range(1, 65536):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((url, port))
            s.close()
        except Exception:
            return 0
    return 1


def check_https_token(host):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return 1
    except Exception:
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
        return 0
    except Exception:
        return 1


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
        return 0
    except Exception:
        return -1
