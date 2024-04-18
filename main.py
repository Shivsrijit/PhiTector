from fastapi import FastAPI
from typing import Optional

import pickle

from utils import *

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

    return {
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
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000)
