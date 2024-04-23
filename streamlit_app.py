import streamlit as st
import pickle
import sqlite3
from utils import *
import pandas as pd

conn = sqlite3.connect("cache.db", check_same_thread=False)
cursor = conn.cursor()
cursor.execute(
    """CREATE TABLE IF NOT EXISTS cache
                  (accuracy INTEGER,
                   url TEXT PRIMARY KEY, 
                   lin_pred INTEGER, 
                   log_pred INTEGER, 
                   knn_pred INTEGER,
                   usingIP INTEGER,
                   longURL INTEGER,
                   shortURL INTEGER,
                   havingAtSymbol INTEGER,
                   doubleSlashRedirect INTEGER,
                   havingDashSymbol INTEGER,
                   havingSubDomain INTEGER,
                   havingSSLCert INTEGER,
                   domainRegLen INTEGER,
                   havingFavicon INTEGER,
                   httpsToken INTEGER,
                   externalObjects INTEGER,
                   anchorTags INTEGER,
                   mouseOver INTEGER,
                   rightClick INTEGER,
                   popupWindow INTEGER,
                   iframe INTEGER,
                   domainLegitimacy INTEGER,
                   dnsRecord INTEGER)"""
)
conn.commit()

with open("lin.pkl", "rb") as f:
    lin_pic = pickle.load(f)

with open("log.pkl", "rb") as f:
    log_pic = pickle.load(f)

with open("knn.pkl", "rb") as f:
    knn_pic = pickle.load(f)


def get_results(url: str, lin_pic, log_pic, knn_pic) -> dict:
    cursor.execute("SELECT * FROM cache WHERE url=?", (url,))
    cached_result = cursor.fetchone()

    if cached_result:
        column_names = [description[0] for description in cursor.description]
        cached_data = dict(zip(column_names, cached_result))
        return cached_data

    using_ip = is_using_ip(url)
    long_url = is_long_url(url)
    short_url = is_shortened_url(url)
    at_symbol = having_at_symbol(url)
    slash_redirect = double_slash_redirect(url)
    dash_symbol = having_dash_symbol(url)
    sub_domain = having_sub_domain(url)
    ssl_cert = having_ssl_cert(url)
    reg_len = get_domain_reg_len(url)
    favicon = check_favicon(url)
    https_token = check_https_token(url)
    external_objects = check_external_objects(url)
    check_tags = check_anchor_tags(url)
    mouse_over = check_fake_url_status_bar(url)
    check_right_click = check_disable_right_click(url)
    check_popup_window = popup_window(url)
    check_iframes = check_invisible_iframes(url)
    domain_legitimacy = check_domain_legitimacy(url)
    dns_record = check_dns_and_whois(url)

    data = pd.DataFrame(
        {
            "UsingIP": [using_ip],
            "LongURL": [long_url],
            "ShortURL": [short_url],
            "Symbol@": [at_symbol],
            "Redirecting//": [slash_redirect],
            "PrefixSuffix-": [dash_symbol],
            "SubDomains": [sub_domain],
            "HTTPS": [ssl_cert],
            "DomainRegLen": [reg_len],
            "Favicon": [favicon],
            "HTTPSDomainURL": [https_token],
            "RequestURL": [external_objects],
            "AnchorURL": [check_tags],
            "StatusBarCust": [mouse_over],
            "DisableRightClick": [check_right_click],
            "UsingPopupWindow": [check_popup_window],
            "IframeRedirection": [check_iframes],
            "AgeofDomain": [domain_legitimacy],
            "DNSRecording": [dns_record],
        }
    )

    lin_pred = lin_pic.predict(data)[0]
    log_pred = int(log_pic.predict(data)[0])
    knn_pred = int(knn_pic.predict(data)[0])

    lin_pred = (lin_pred + 1) / 2

    accuracy = (lin_pred + log_pred + knn_pred) / 3

    if accuracy > 1:
        accuracy = 1
    elif accuracy < 0:
        accuracy = 0

    cursor.execute(
        "INSERT OR REPLACE INTO cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            accuracy,
            url,
            lin_pred,
            log_pred,
            knn_pred,
            using_ip,
            long_url,
            short_url,
            at_symbol,
            slash_redirect,
            dash_symbol,
            sub_domain,
            ssl_cert,
            reg_len,
            favicon,
            https_token,
            external_objects,
            check_tags,
            mouse_over,
            check_right_click,
            check_popup_window,
            check_iframes,
            domain_legitimacy,
            dns_record,
        ),
    )

    conn.commit()

    return {
        "accuracy": accuracy,
        "url": url,
        "lin_pred": lin_pred,
        "log_pred": log_pred,
        "knn_pred": knn_pred,
        "usingIP": using_ip,
        "longURL": long_url,
        "shortURL": short_url,
        "havingAtSymbol": at_symbol,
        "doubleSlashRedirect": slash_redirect,
        "havingDashSymbol": dash_symbol,
        "havingSubDomain": sub_domain,
        "havingSSLCert": ssl_cert,
        "domainRegLen": reg_len,
        "havingFavicon": favicon,
        "httpsToken": https_token,
        "externalObjects": external_objects,
        "anchorTags": check_tags,
        "mouseOver": mouse_over,
        "rightClick": check_right_click,
        "popupWindow": check_popup_window,
        "iframe": check_iframes,
        "domainLegitimacy": domain_legitimacy,
        "dnsRecord": dns_record,
    }


st.title("PhiTector - Detect Phishing Links")
st.subheader("Enter a URL below and check the possibility of it being a phishing link")

url = st.text_input(label="URL")

if st.button("Check"):
    if not url:
        st.error("Please provide a URL")
    else:
        cursor.execute("SELECT * FROM cache WHERE url=?", (url,))
        cached_result = cursor.fetchone()

        if cached_result:
            column_names = [description[0] for description in cursor.description]
            cached_data = dict(zip(column_names, cached_result))
            st.write(cached_data)
        else:
            results = get_results(url, lin_pic, log_pic, knn_pic)
            st.write(results)
