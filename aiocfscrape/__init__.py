from base64 import b64encode
from urllib.parse import urlparse, urlunparse

import httpx
import asyncio
import copy
import js2py
import logging
import random
import re
import time
from latest_user_agents import get_latest_user_agents


DEFAULT_USER_AGENT = random.choice(get_latest_user_agents())

DEFAULT_HEADERS = {
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
}


class CloudflareCaptchaError(httpx.HTTPStatusError):
    def __init__(self, message, response):
        super().__init__(message=message, request=response.request, response=response)


class CloudflareScraper(httpx.AsyncClient):
    def __init__(self, *args, headers=None, **kwargs):
        headers = headers or dict(DEFAULT_HEADERS)
        super().__init__(*args, headers=headers, **kwargs)
        self.org_method = None
        self.delay = None

    async def request(self, method, url, *args, allow_403=False, **kwargs):
        resp = await super().request(method, url, *args, **kwargs)
        await resp.aread()

        if await self.is_cloudflare_captcha_challenge(resp, allow_403):
            self.handle_captcha_challenge(resp, url)
        elif await self.is_cloudflare_iuam_challenge(resp):
            return await self.solve_cf_challenge(resp, **kwargs)
        return resp

    async def is_cloudflare_iuam_challenge(self, resp):
        await resp.aread()
        return (
            resp.status_code in (503, 429)
            and resp.headers.get("Server", "").startswith("cloudflare")
            and b"jschl_vc" in resp.content
            and b"jschl_answer" in resp.content
        )

    async def is_cloudflare_captcha_challenge(self, resp, allow_403):
        await resp.aread()
        return (
            resp.status_code == 403
            and not allow_403
            and resp.headers.get("Server", "").startswith("cloudflare")
            and b"/cdn-cgi/l/chk_captcha" in resp.content
        )

    def handle_captcha_challenge(self, resp, url):
        error = (
            "Cloudflare captcha challenge presented for %s (cfscrape cannot solve captchas)"
            % urlparse(url).netloc
        )
        raise CloudflareCaptchaError(message=error, response=resp)

    async def solve_cf_challenge(self, resp, **original_kwargs):
        start_time = time.time()
        body = resp.text
        parsed_url = urlparse(resp.url)
        domain = parsed_url.netloc

        challenge_form_match = re.search(
            r"\<form.*?id=\"challenge-form\".*?\/form\>", body, flags=re.S
        )
        if not challenge_form_match:
            raise ValueError("Unable to find challenge form in response")
        challenge_form = challenge_form_match.group(0)

        method_match = re.search(r"method=\"(.*?)\"", challenge_form, flags=re.S)
        if not method_match:
            raise ValueError("Unable to find method in challenge form")
        method = method_match.group(1)

        if self.org_method is None:
            self.org_method = resp.request.method

        action_match = re.search(r"action=\"(.*?)\"", challenge_form, flags=re.S)
        if not action_match:
            raise ValueError("Unable to find action in challenge form")
        submit_url = "%s://%s%s" % (
            parsed_url.scheme,
            domain,
            action_match.group(1).split("?")[0],
        )

        cloudflare_kwargs = copy.deepcopy(original_kwargs)
        headers = cloudflare_kwargs.setdefault("headers", {})
        headers["Referer"] = str(resp.url)

        try:
            cloudflare_kwargs["params"] = {}
            cloudflare_kwargs["data"] = {}

            action_url = action_match.group(1)
            if len(action_url.split("?")) != 1:
                for param in action_url.split("?")[1].split("&"):
                    cloudflare_kwargs["params"][param.split("=")[0]] = param.split("=")[
                        1
                    ]

            for input_ in re.findall(
                r"\<input.*?(?:\/>|\<\/input\>)", challenge_form, flags=re.S
            ):
                name_match = re.search(r"name=\"(.*?)\"", input_, flags=re.S)
                if not name_match:
                    continue
                name = name_match.group(1)
                if name != "jschl_answer":
                    value_match = re.search(r"value=\"(.*?)\"", input_, flags=re.S)
                    if not value_match:
                        continue
                    value = value_match.group(1)
                    if method == "POST":
                        cloudflare_kwargs["data"][name] = value
                    elif method == "GET":
                        cloudflare_kwargs["params"][name] = value
            if method == "POST":
                for k in ("jschl_vc", "pass"):
                    if k not in cloudflare_kwargs["data"]:
                        raise ValueError("%s is missing from challenge form" % k)
            elif method == "GET":
                for k in ("jschl_vc", "pass"):
                    if k not in cloudflare_kwargs["params"]:
                        raise ValueError("%s is missing from challenge form" % k)

        except Exception as e:
            raise ValueError(
                "Unable to parse Cloudflare anti-bot IUAM page: %s " % (e)
            )

        answer, delay = self.solve_challenge(body, domain)
        if method == "POST":
            cloudflare_kwargs["data"]["jschl_answer"] = answer
        elif method == "GET":
            cloudflare_kwargs["params"]["jschl_answer"] = answer

        cloudflare_kwargs["follow_redirects"] = False

        await asyncio.sleep(max(delay - (time.time() - start_time), 0))

        redirect = await self.request(method, submit_url, **cloudflare_kwargs)
        await redirect.aread()
        if "Location" in redirect.headers:
            redirect_location = urlparse(redirect.headers["Location"])
            if not redirect_location.netloc:
                redirect_url = urlunparse(
                    (
                        parsed_url.scheme,
                        domain,
                        redirect_location.path,
                        redirect_location.params,
                        redirect_location.query,
                        redirect_location.fragment,
                    )
                )
                return await self.request(
                    self.org_method, redirect_url, **original_kwargs
                )
            return await self.request(
                self.org_method, redirect.headers["Location"], **original_kwargs
            )
        elif (
            "Set-Cookie" in redirect.headers
            and "cf_clearance" in redirect.headers["Set-Cookie"]
        ):
            self.cookies.update(redirect.cookies)
            return await self.request(self.org_method, submit_url, **original_kwargs)
        else:
            return await self.request(self.org_method, submit_url, **cloudflare_kwargs)

    def solve_challenge(self, body, domain):
        try:
            javascript_match = re.search(
                r"\<script type\=\"text\/javascript\"\>\n(.*?)\<\/script\>",
                body,
                flags=re.S,
            )
            if not javascript_match:
                raise ValueError("Unable to find JavaScript in response")
            javascript = javascript_match.group(1)

            challenge_match = re.search(
                r"setTimeout\(function\(\){\s*(var "
                r"s,t,o,p,b,r,e,a,k,i,n,g,f.+?\r?\n[\s\S]+?a\.value\s*=.+?)\r?\n"
                r"(?:[^{<>]*},\s*(\d{4,}))?",
                javascript,
                flags=re.S,
            )
            if not challenge_match:
                raise ValueError("Unable to find challenge in JavaScript")
            challenge, ms = challenge_match.groups()

            innerHTML = ""
            for i in javascript.split(";"):
                if i.strip().split("=")[0].strip() == "k":
                    k = i.strip().split("=")[1].strip(" '")
                    innerHTML_match = re.search(
                        r"\<div.*?id\=\"%s\".*?\>(.*?)\<\/div\>" % k, body
                    )
                    if innerHTML_match:
                        innerHTML = innerHTML_match.group(1)
            challenge = """
                var document = {
                    createElement: function () {
                      return { firstChild: { href: "http://%s/" } }
                    },
                    getElementById: function () {
                      return {"innerHTML": "%s"};
                    }
                  };
                %s; a.value
            """ % (
                domain,
                innerHTML,
                challenge,
            )
            challenge = b64encode(challenge.encode("utf-8")).decode("ascii")
            delay = self.delay or (float(ms) / float(1000) if ms else 8)
        except Exception:
            raise ValueError(
                "Unable to identify Cloudflare IUAM Javascript on website."
                
            )
        js = (
            """\
            var atob = Object.setPrototypeOf(function (str) {\
                try {\
                    return Buffer.from("" + str, "base64").toString("binary");\
                } catch (e) {}\
            }, null);\
            var challenge = atob("%s");\
            var context = Object.setPrototypeOf({ atob: atob }, null);\
            var options = {\
                filename: "iuam-challenge.js",\
                contextOrigin: "cloudflare:iuam-challenge.js",\
                contextCodeGeneration: { strings: true, wasm: false },\
                timeout: 5000\
            };\
            process.stdout.write(String(\
                require("vm").runInNewContext(challenge, context, options)\
            ));\
        """
            % challenge
        )
        try:
            result = js2py.eval_js(js)
        except Exception:
            logging.error("Error executing Cloudflare IUAM Javascript. ")
            raise
        try:
            float(result)
        except Exception:
            raise ValueError(
                "Cloudflare IUAM challenge returned unexpected answer. " 
            )
        return result, delay
