import ipaddress
import re
import socket
import warnings
from datetime import date, datetime
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from googlesearch import search
import whois

warnings.filterwarnings("ignore")


FEATURE_NAMES = [
    "UsingIP",
    "LongURL",
    "ShortURL",
    "Symbol@",
    "Redirecting//",
    "PrefixSuffix-",
    "SubDomains",
    "HTTPS",
    "DomainRegLen",
    "Favicon",
    "NonStdPort",
    "HTTPSDomainURL",
    "RequestURL",
    "AnchorURL",
    "LinksInScriptTags",
    "ServerFormHandler",
    "InfoEmail",
    "AbnormalURL",
    "WebsiteForwarding",
    "StatusBarCust",
    "DisableRightClick",
    "UsingPopupWindow",
    "IframeRedirection",
    "AgeofDomain",
    "DNSRecording",
    "WebsiteTraffic",
    "PageRank",
    "GoogleIndex",
    "LinksPointingToPage",
    "StatsReport"
]


class FeatureExtraction:

    def __init__(self, url):

        self.features = []
        self.url = url.strip()

        self.domain = ""
        self.whois_response = None
        self.urlparse = None
        self.response = None
        self.soup = None

        self.is_non_url = False

        # --------------------------------------------------
        # Check whether the input is a normal web URL
        # --------------------------------------------------
        if not re.match(r"^(https?|ftp)://", self.url, re.IGNORECASE):
            self.is_non_url = True
            self.features = [0] * 30
            return

        # --------------------------------------------------
        # Parse URL
        # --------------------------------------------------
        try:
            self.urlparse = urlparse(self.url)

            self.domain = (
                self.urlparse.hostname
                or self.urlparse.netloc
                or ""
            )

        except Exception:
            self.domain = ""

        # --------------------------------------------------
        # Fetch website
        # --------------------------------------------------
        try:

            self.response = requests.get(
                self.url,
                timeout=5,
                headers={
                    "User-Agent":
                    "Mozilla/5.0 AegisShield Security Scanner"
                },
                allow_redirects=True
            )

            self.soup = BeautifulSoup(
                self.response.text,
                "html.parser"
            )

        except Exception:

            self.response = None
            self.soup = None

        # --------------------------------------------------
        # WHOIS
        # --------------------------------------------------
        if self.domain:

            try:
                self.whois_response = whois.whois(
                    self.domain
                )

            except Exception:
                self.whois_response = None

        # --------------------------------------------------
        # Feature methods
        # --------------------------------------------------
        feature_methods = {

            "UsingIP": self.UsingIp,
            "LongURL": self.longUrl,
            "ShortURL": self.shortUrl,
            "Symbol@": self.symbol,
            "Redirecting//": self.redirecting,
            "PrefixSuffix-": self.prefixSuffix,
            "SubDomains": self.SubDomains,
            "HTTPS": self.Hppts,
            "DomainRegLen": self.DomainRegLen,
            "Favicon": self.Favicon,
            "NonStdPort": self.NonStdPort,
            "HTTPSDomainURL": self.HTTPSDomainURL,
            "RequestURL": self.RequestURL,
            "AnchorURL": self.AnchorURL,
            "LinksInScriptTags": self.LinksInScriptTags,
            "ServerFormHandler": self.ServerFormHandler,
            "InfoEmail": self.InfoEmail,
            "AbnormalURL": self.AbnormalURL,
            "WebsiteForwarding": self.WebsiteForwarding,
            "StatusBarCust": self.StatusBarCust,
            "DisableRightClick": self.DisableRightClick,
            "UsingPopupWindow": self.UsingPopupWindow,
            "IframeRedirection": self.IframeRedirection,
            "AgeofDomain": self.AgeofDomain,
            "DNSRecording": self.DNSRecording,
            "WebsiteTraffic": self.WebsiteTraffic,
            "PageRank": self.PageRank,
            "GoogleIndex": self.GoogleIndex,
            "LinksPointingToPage": self.LinksPointingToPage,
            "StatsReport": self.StatsReport
        }

        # --------------------------------------------------
        # Extract exactly 30 features
        # --------------------------------------------------
        self.features = []

        for name in FEATURE_NAMES:

            method = feature_methods[name]

            try:

                value = method()

                if value not in [-1, 0, 1]:
                    value = 0

                self.features.append(value)

            except Exception:

                self.features.append(0)

        assert len(self.features) == 30


    # ======================================================
    # 1. Using IP
    # ======================================================

    def UsingIp(self):

        try:

            hostname = self.domain

            if not hostname and self.urlparse:
                hostname = self.urlparse.hostname

            if not hostname:
                return 0

            ipaddress.ip_address(hostname)

            return -1

        except Exception:

            return 1


    # ======================================================
    # 2. Long URL
    # ======================================================

    def longUrl(self):

        length = len(self.url)

        if length < 54:
            return 1

        elif length <= 75:
            return 0

        return -1


    # ======================================================
    # 3. Short URL
    # ======================================================

    def shortUrl(self):

        pattern = (
            r"bit\.ly|goo\.gl|tinyurl|t\.co|ow\.ly|"
            r"is\.gd|bit\.do|lnkd\.in|db\.tt|qr\.ae|"
            r"adf\.ly|tinyurl\.com|bitly\.com"
        )

        if re.search(pattern, self.url, re.IGNORECASE):
            return -1

        return 1


    # ======================================================
    # 4. @ Symbol
    # ======================================================

    def symbol(self):

        if "@" in self.url:
            return -1

        return 1


    # ======================================================
    # 5. Redirecting //
    # ======================================================

    def redirecting(self):

        try:

            if self.url.rfind("//") > 7:
                return -1

            return 1

        except Exception:

            return 0


    # ======================================================
    # 6. Prefix / Suffix
    # ======================================================

    def prefixSuffix(self):

        if "-" in self.domain:
            return -1

        return 1


    # ======================================================
    # 7. Subdomains
    # ======================================================

    def SubDomains(self):

        try:

            domain = self.domain

            if domain.startswith("www."):
                domain = domain[4:]

            dots = domain.count(".")

            if dots <= 1:
                return 1

            elif dots == 2:
                return 0

            return -1

        except Exception:

            return 0


    # ======================================================
    # 8. HTTPS
    # ======================================================

    def Hppts(self):

        try:

            if (
                self.urlparse
                and self.urlparse.scheme.lower() == "https"
            ):
                return 1

            return -1

        except Exception:

            return 0


    # ======================================================
    # 9. Domain Registration Length
    # ======================================================

    def DomainRegLen(self):

        try:

            if not self.whois_response:
                return 0

            expiration = self.whois_response.expiration_date
            creation = self.whois_response.creation_date

            if not expiration or not creation:
                return 0

            if isinstance(expiration, list):
                expiration = expiration[0]

            if isinstance(creation, list):
                creation = creation[0]

            difference = (expiration - creation).days

            if difference >= 365:
                return 1

            return -1

        except Exception:

            return 0


    # ======================================================
    # 10. Favicon
    # ======================================================

    def Favicon(self):

        try:

            # Website could not be downloaded
            if not self.soup:
                return 0

            for link in self.soup.find_all(
                "link",
                rel=re.compile(r"icon", re.IGNORECASE)
            ):

                href = link.get("href", "")

                if not href:
                    continue

                parsed_href = urlparse(href)

                if (
                    parsed_href.netloc
                    and parsed_href.netloc != self.domain
                ):
                    return -1

            return 1

        except Exception:

            return 0


    # ======================================================
    # 11. Non Standard Port
    # ======================================================

    def NonStdPort(self):

        try:

            if not self.urlparse:
                return 0

            port = self.urlparse.port

            if port is None:
                return 1

            if port in [80, 443]:
                return 1

            return -1

        except Exception:

            return 0


    # ======================================================
    # 12. HTTPS in Domain
    # ======================================================

    def HTTPSDomainURL(self):

        if "https" in self.domain.lower():
            return -1

        return 1


    # ======================================================
    # 13. Request URL
    # ======================================================

    def RequestURL(self):

        try:

            if not self.soup:
                return 0

            total = 0
            external = 0

            for tag in ["img", "audio", "embed", "iframe"]:

                for element in self.soup.find_all(
                    tag,
                    src=True
                ):

                    src = element["src"]

                    parsed = urlparse(src)

                    total += 1

                    if (
                        parsed.netloc
                        and parsed.netloc != self.domain
                    ):
                        external += 1

            if total == 0:
                return 1

            percentage = (
                external / float(total)
            ) * 100

            if percentage < 22:
                return 1

            elif percentage < 61:
                return 0

            return -1

        except Exception:

            return 0


    # ======================================================
    # 14. Anchor URL
    # ======================================================

    def AnchorURL(self):

        try:

            if not self.soup:
                return 0

            total = 0
            unsafe = 0

            for anchor in self.soup.find_all(
                "a",
                href=True
            ):

                href = anchor["href"].strip()

                total += 1

                if (
                    href.startswith("#")
                    or href.startswith("javascript:")
                    or href.startswith("mailto:")
                ):

                    unsafe += 1

            if total == 0:
                return 1

            percentage = (
                unsafe / float(total)
            ) * 100

            if percentage < 31:
                return 1

            elif percentage < 67:
                return 0

            return -1

        except Exception:

            return 0


    # ======================================================
    # 15. Links in Script Tags
    # ======================================================

    def LinksInScriptTags(self):

        try:

            if not self.soup:
                return 0

            total = 0
            external = 0

            for tag in ["meta", "script", "link"]:

                for element in self.soup.find_all(tag):

                    href = (
                        element.get("href")
                        or element.get("src")
                    )

                    if href:

                        total += 1

                        parsed = urlparse(href)

                        if (
                            parsed.netloc
                            and parsed.netloc != self.domain
                        ):
                            external += 1

            if total == 0:
                return 1

            percentage = (
                external / float(total)
            ) * 100

            if percentage < 17:
                return 1

            elif percentage <= 81:
                return 0

            return -1

        except Exception:

            return 0


    # ======================================================
    # 16. Server Form Handler
    # ======================================================

    def ServerFormHandler(self):

        try:

            if not self.soup:
                return 0

            forms = self.soup.find_all(
                "form",
                action=True
            )

            if not forms:
                return 1

            for form in forms:

                action = form["action"].strip()

                if (
                    action == ""
                    or action.lower() == "about:blank"
                ):
                    return -1

                parsed = urlparse(action)

                if (
                    parsed.netloc
                    and parsed.netloc != self.domain
                ):
                    return 0

            return 1

        except Exception:

            return 0


    # ======================================================
    # 17. Information Email
    # ======================================================

    def InfoEmail(self):

        try:

            if "mailto:" in self.url.lower():
                return -1

            if (
                self.response
                and "mailto:" in self.response.text.lower()
            ):
                return -1

            return 1

        except Exception:

            return 0


    # ======================================================
    # 18. Abnormal URL
    # ======================================================

    def AbnormalURL(self):

        try:

            if not self.whois_response:
                return 0

            whois_domain = (
                self.whois_response.domain_name
            )

            if isinstance(whois_domain, list):

                domains = [
                    str(d).lower()
                    for d in whois_domain
                ]

            elif isinstance(whois_domain, str):

                domains = [
                    whois_domain.lower()
                ]

            else:

                domains = []

            current = self.domain.lower()

            for domain in domains:

                if current == domain:
                    return 1

                if current in domain:
                    return 1

            return -1

        except Exception:

            return 0


    # ======================================================
    # 19. Website Forwarding
    # ======================================================

    def WebsiteForwarding(self):

        try:

            if not self.response:
                return 0

            redirects = len(
                self.response.history
            )

            if redirects <= 1:
                return 1

            elif redirects <= 3:
                return 0

            return -1

        except Exception:

            return 0


    # ======================================================
    # 20. Status Bar Customization
    # ======================================================

    def StatusBarCust(self):

        try:

            if not self.response:
                return 0

            text = self.response.text.lower()

            if "window.status" in text:
                return -1

            if self.soup:

                for element in self.soup.find_all(
                    onmouseover=True
                ):

                    value = element.get(
                        "onmouseover",
                        ""
                    ).lower()

                    if "window.status" in value:
                        return -1

            return 1

        except Exception:

            return 0


    # ======================================================
    # 21. Disable Right Click
    # ======================================================

    def DisableRightClick(self):

        try:

            if not self.response:
                return 0

            text = self.response.text.lower()

            if (
                "contextmenu" in text
                and "preventdefault" in text
            ):
                return -1

            return 1

        except Exception:

            return 0


    # ======================================================
    # 22. Popup Window
    # ======================================================

    def UsingPopupWindow(self):

        try:

            if not self.response:
                return 0

            text = self.response.text.lower()

            if (
                "prompt(" in text
                or "window.open(" in text
            ):
                return -1

            return 1

        except Exception:

            return 0


    # ======================================================
    # 23. Iframe Redirection
    # ======================================================

    def IframeRedirection(self):

        try:

            if not self.soup:
                return 0

            if self.soup.find("iframe"):
                return -1

            return 1

        except Exception:

            return 0


    # ======================================================
    # 24. Age of Domain
    # ======================================================

    def AgeofDomain(self):

        try:

            if not self.whois_response:
                return 0

            creation = (
                self.whois_response.creation_date
            )

            if not creation:
                return 0

            if isinstance(creation, list):
                creation = creation[0]

            if isinstance(creation, datetime):
                creation = creation.date()

            age_days = (
                date.today() - creation
            ).days

            if age_days >= 180:
                return 1

            return -1

        except Exception:

            return 0


# ======================================================
    # 25. DNS Recording
    # ======================================================

    # ======================================================
    # 25. DNS Recording
    # ======================================================

    def DNSRecording(self):

        try:

            if not self.domain:
                return 0

            socket.gethostbyname(self.domain)

            return 1

        except Exception:

            return 0
        # ======================================================
    # 26. Website Traffic
    # ======================================================

    def WebsiteTraffic(self):

        try:
            return 0
        except Exception:
            return 0


    # ======================================================
    # 27. PageRank
    # ======================================================

    def PageRank(self):

        try:
            return 0
        except Exception:
            return 0


    # ======================================================
    # 28. Google Index
    # ======================================================

    def GoogleIndex(self):

        try:
            return 0
        except Exception:
            return 0


    # ======================================================
    # 29. Links Pointing To Page
    # ======================================================

    def LinksPointingToPage(self):

        try:

            if not self.soup:
                return 0

            links = self.soup.find_all("a", href=True)

            if len(links) == 0:
                return 0

            return 1

        except Exception:
            return 0


    # ======================================================
    # 30. Stats Report
    # ======================================================

    def StatsReport(self):

        try:
            return 0
        except Exception:
            return 0


    # ======================================================
    # Get Features List
    # ======================================================

    def getFeaturesList(self):

        return self.features