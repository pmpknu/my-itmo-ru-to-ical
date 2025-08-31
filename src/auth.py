import html
import logging
import os
import re
import urllib.parse
from base64 import urlsafe_b64encode
from hashlib import sha256

from aiohttp import ClientSession
from cache import AsyncTTL

logger = logging.getLogger(__name__)

# inspired by https://www.stefaanlippens.net/oauth-code-flow-pkce.html

_CLIENT_ID = "student-personal-cabinet"
_REDIRECT_URI = "https://my.itmo.ru/login/callback"
_PROVIDER = "https://id.itmo.ru/auth/realms/itmo"


def generate_code_verifier():
    code_verifier = urlsafe_b64encode(os.urandom(40)).decode("utf-8")
    return re.sub("[^a-zA-Z0-9]+", "", code_verifier)


def get_code_challenge(code_verifier: str):
    code_challenge_bytes = sha256(code_verifier.encode("utf-8")).digest()
    code_challenge = urlsafe_b64encode(code_challenge_bytes).decode("utf-8")
    return code_challenge.replace("=", "")  # remove base64 padding


_FORM_ACTION_REGEX = re.compile(rf'"loginAction":\s*"(?P<action>{re.escape(_PROVIDER)}[^"]*)"', re.DOTALL)


@AsyncTTL(time_to_live=55 * 60, skip_args=1)
async def get_access_token(session: ClientSession, username: str, password: str) -> str:
    logger.info(f"Getting new access token for {username}")

    code_verifier = generate_code_verifier()
    code_challenge = get_code_challenge(code_verifier)

    auth_resp = await session.get(
        _PROVIDER + "/protocol/openid-connect/auth",
        params=dict(
            protocol="oauth2",
            response_type="code",
            client_id=_CLIENT_ID,
            redirect_uri=_REDIRECT_URI,
            scope="openid",
            state="im_not_a_browser",
            code_challenge_method="S256",
            code_challenge=code_challenge,
        ),
    )
    auth_resp.raise_for_status()

    form_action_match = _FORM_ACTION_REGEX.search(await auth_resp.text())
    assert form_action_match, "Keycloak form action regexp match not found"
    form_action = html.unescape(form_action_match.group("action"))

    form_resp = await session.post(
        url=form_action,
        data=dict(username=username, password=password),
        cookies=auth_resp.cookies,
        allow_redirects=False,
    )
    if form_resp.status != 302:
        raise ValueError(f"Wrong Keycloak form response: {form_resp.status} {await form_resp.text()}")

    url_redirected_to = form_resp.headers["Location"]
    query = urllib.parse.urlparse(url_redirected_to).query
    redirect_params = urllib.parse.parse_qs(query)
    auth_code = redirect_params["code"][0]

    token_resp = await session.post(
        url=_PROVIDER + "/protocol/openid-connect/token",
        data=dict(
            grant_type="authorization_code",
            client_id=_CLIENT_ID,
            redirect_uri=_REDIRECT_URI,
            code=auth_code,
            code_verifier=code_verifier,
        ),
        allow_redirects=False,
    )
    token_resp.raise_for_status()
    result = await token_resp.json()
    token = result["access_token"]
    logger.info(f"Got new access token for {username} successfully")
    return token
