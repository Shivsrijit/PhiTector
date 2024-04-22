from fastapi import FastAPI
from typing import Optional

import numpy as np
import pickle
import sqlite3

from utils import *

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
                   port INTEGER,
                   httpsToken INTEGER,
                   externalObjects INTEGER,
                   anchorTags INTEGER,
                   metadata INTEGER,
                   suspiciousSFH INTEGER,
                   emailSubmission INTEGER,
                   legitimateWebsite INTEGER,
                   redirectLegitimacy INTEGER,
                   mouseOver INTEGER,
                   rightClick INTEGER,
                   popupWindow INTEGER,
                   iframe INTEGER,
                   domainLegitimacy INTEGER,
                   dnsRecord INTEGER,
                   ranking INTEGER,
                   pageRank INTEGER,
                   googleIndex INTEGER)"""
)
conn.commit()

app = FastAPI()

with open("lin.pkl", "rb") as f:
    lin_pic = pickle.load(f)

with open("log.pkl", "rb") as f:
    log_pic = pickle.load(f)

with open("knn.pkl", "rb") as f:
    knn_pic = pickle.load(f)


@app.get("/")
def index(url: Optional[str] = None) -> dict:
    if not url:
        return {"error": "Please provide a url"}

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
    sockets = check_all_ports_open(url)
    https_token = check_https_token(url)
    external_objects = check_external_objects(url)
    check_tags = check_anchor_tags(url)
    metadata = check_metadata_tags(url)
    susp_sfh = check_suspicious_sfh(url)
    email_submission = submit_to_email(url)
    legitimate_website = check_legitimate_website(url)
    redirect_legitimacy = check_redirects_legitimacy(url)
    mouse_over = check_fake_url_status_bar(url)
    check_right_click = check_disable_right_click(url)
    check_popup_window = popup_window(url)
    check_iframes = check_invisible_iframes(url)
    domain_legitimacy = check_domain_legitimacy(url)
    dns_record = check_dns_and_whois(url)
    check_ranking = check_alexa_rank(url)
    page_ranking = get_page_rank(url)
    google_index = check_google_index(url)

    arr = [
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
        sockets,
        https_token,
        external_objects,
        check_tags,
        metadata,
        susp_sfh,
        email_submission,
        legitimate_website,
        redirect_legitimacy,
        mouse_over,
        check_right_click,
        check_popup_window,
        check_iframes,
        domain_legitimacy,
        dns_record,
        check_ranking,
        page_ranking,
        google_index,
    ]

    x_val = np.array(arr).reshape(1, -1)

    lin_pred = int(lin_pic.predict(x_val)[0])
    log_pred = int(log_pic.predict(x_val)[0])
    knn_pred = int(knn_pic.predict(x_val)[0])

    accuracy = (
        0.927003573251659 * lin_pred
        + 0.9285349668198061 * log_pred
        + 0.9683511995916284 * knn_pred
    ) / 3

    print(lin_pred)
    print(log_pred)
    print(knn_pred)

    cursor.execute(
        "INSERT OR REPLACE INTO cache VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            sockets,
            https_token,
            external_objects,
            check_tags,
            metadata,
            susp_sfh,
            email_submission,
            legitimate_website,
            redirect_legitimacy,
            mouse_over,
            check_right_click,
            check_popup_window,
            check_iframes,
            domain_legitimacy,
            dns_record,
            check_ranking,
            page_ranking,
            google_index,
        ),
    )

    conn.commit()

    return {
        "accuracy": accuracy,
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
        "port": sockets,
        "httpsToken": https_token,
        "externalObjects": external_objects,
        "anchorTags": check_tags,
        "metadata": metadata,
        "sucpiciousSFH": susp_sfh,
        "emailSubmission": email_submission,
        "legitimateWebsite": legitimate_website,
        "redirectLegitimacy": redirect_legitimacy,
        "mouseOver": mouse_over,
        "rightClick": check_right_click,
        "popupWindow": check_popup_window,
        "iframe": check_iframes,
        "domainLegitimacy": domain_legitimacy,
        "dnsRecord": dns_record,
        "ranking": check_ranking,
        "pageRank": page_ranking,
        "googleIndex": google_index,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000)
