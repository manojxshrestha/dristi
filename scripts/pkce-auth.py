#!/usr/bin/env python3
"""
PKCE Authentication Helper for OAuth 2.0 / Keycloak / OIDC.

Performs the full Authorization Code flow with PKCE:
1. Generates code_verifier and code_challenge
2. Initiates the authorization request
3. Parses the login form from the auth provider
4. Submits credentials
5. Captures the authorization code from the callback redirect
6. Exchanges the code + code_verifier for tokens

Usage:
    python3 pkce-auth.py \\
        --auth-url https://auth.example.com \\
        --realm my-realm \\
        --client-id my-app \\
        --username user@example.com \\
        --password secret123 \\
        --redirect-uri https://app.example.com/callback \\
        [--cookie-jar ./engagements/<eid>/cookies.txt] \\
        [--scope "openid profile email"] \\
        [--output-format token|cookie|both|json]
"""

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import sys
import urllib.parse
from http.cookiejar import MozillaCookieJar

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def generate_pkce_pair():
    """Generate PKCE code_verifier and code_challenge."""
    code_verifier = secrets.token_urlsafe(32)
    code_challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(code_verifier.encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    return code_verifier, code_challenge


def discover_oidc_config(auth_url, realm=None):
    """Fetch the OIDC well-known configuration."""
    urls_to_try = []
    if realm:
        urls_to_try.append(
            f"{auth_url}/realms/{realm}/.well-known/openid-configuration"
        )
    urls_to_try.append(f"{auth_url}/.well-known/openid-configuration")

    for url in urls_to_try:
        try:
            resp = requests.get(url, verify=False, timeout=10)
            if resp.status_code == 200:
                return resp.json()
        except requests.RequestException:
            continue
    return None


def extract_form_action(html):
    """Extract the form action URL from an HTML login page."""
    match = re.search(r'<form[^>]*action="([^"]*)"', html, re.IGNORECASE)
    if match:
        action = match.group(1)
        action = action.replace("&amp;", "&")
        return action
    return None


def extract_hidden_fields(html):
    """Extract hidden form fields from HTML."""
    fields = {}
    # Match: <input type="hidden" name="X" value="Y">
    for match in re.finditer(
        r'<input[^>]*type=["\']hidden["\'][^>]*name=["\']([^"\']*)["\'][^>]*value=["\']([^"\']*)["\']',
        html,
        re.IGNORECASE,
    ):
        fields[match.group(1)] = match.group(2)
    # Match reversed order: <input name="X" type="hidden" value="Y">
    for match in re.finditer(
        r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']hidden["\'][^>]*value=["\']([^"\']*)["\']',
        html,
        re.IGNORECASE,
    ):
        if match.group(1) not in fields:
            fields[match.group(1)] = match.group(2)
    # Match: <input value="Y" name="X" type="hidden">
    for match in re.finditer(
        r'<input[^>]*value=["\']([^"\']*)["\'][^>]*name=["\']([^"\']*)["\'][^>]*type=["\']hidden["\']',
        html,
        re.IGNORECASE,
    ):
        if match.group(2) not in fields:
            fields[match.group(2)] = match.group(1)
    return fields


def detect_username_field(html):
    """Detect the username field name from the login form."""
    # Common patterns for username/email fields
    for pattern in [
        r'<input[^>]*name=["\']([^"\']*(?:user|email|login)[^"\']*)["\'][^>]*type=["\'](?:text|email)["\']',
        r'<input[^>]*type=["\'](?:text|email)["\'][^>]*name=["\']([^"\']*(?:user|email|login)[^"\']*)["\']',
        r'<input[^>]*name=["\']([^"\']*)["\'][^>]*id=["\'](?:user|email|login|username)["\']',
    ]:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)
    return "username"


def detect_password_field(html):
    """Detect the password field name from the login form."""
    match = re.search(
        r'<input[^>]*name=["\']([^"\']*)["\'][^>]*type=["\']password["\']',
        html,
        re.IGNORECASE,
    )
    if match:
        return match.group(1)
    match = re.search(
        r'<input[^>]*type=["\']password["\'][^>]*name=["\']([^"\']*)["\']',
        html,
        re.IGNORECASE,
    )
    if match:
        return match.group(1)
    return "password"


def main():
    parser = argparse.ArgumentParser(
        description="PKCE OAuth2 Authentication Helper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Keycloak with PKCE
  python3 pkce-auth.py --auth-url https://keycloak.example.com \\
    --realm myrealm --client-id my-app \\
    --username user@example.com --password secret \\
    --redirect-uri https://app.example.com/callback

  # Output only the access token
  python3 pkce-auth.py ... --output-format token

  # Save session cookies to jar
  python3 pkce-auth.py ... --cookie-jar ./cookies.txt
        """,
    )
    parser.add_argument("--auth-url", required=True, help="Auth provider base URL")
    parser.add_argument("--realm", help="Keycloak realm name")
    parser.add_argument("--client-id", required=True, help="OAuth client ID")
    parser.add_argument("--username", required=True, help="Username or email")
    parser.add_argument("--password", required=True, help="Password")
    parser.add_argument("--redirect-uri", required=True, help="OAuth redirect URI")
    parser.add_argument("--scope", default="openid", help="OAuth scopes (default: openid)")
    parser.add_argument("--cookie-jar", help="Path to save cookies (Netscape format)")
    parser.add_argument(
        "--output-format",
        choices=["token", "cookie", "both", "json"],
        default="json",
        help="Output format (default: json)",
    )
    args = parser.parse_args()

    session = requests.Session()
    session.verify = False

    # Load cookie jar if specified
    if args.cookie_jar:
        cookie_jar = MozillaCookieJar(args.cookie_jar)
        if os.path.exists(args.cookie_jar):
            try:
                cookie_jar.load(ignore_discard=True, ignore_expires=True)
            except Exception:
                pass  # Empty or malformed jar, start fresh
        session.cookies = cookie_jar

    # Step 1: Discover OIDC configuration
    print("[*] Step 1: Discovering OIDC configuration...", file=sys.stderr)
    oidc_config = discover_oidc_config(args.auth_url, args.realm)
    if oidc_config:
        auth_endpoint = oidc_config.get("authorization_endpoint")
        token_endpoint = oidc_config.get("token_endpoint")
        print(f"    Authorization: {auth_endpoint}", file=sys.stderr)
        print(f"    Token: {token_endpoint}", file=sys.stderr)
    else:
        if args.realm:
            base = f"{args.auth_url}/realms/{args.realm}/protocol/openid-connect"
        else:
            base = f"{args.auth_url}/protocol/openid-connect"
        auth_endpoint = f"{base}/auth"
        token_endpoint = f"{base}/token"
        print("    Using constructed endpoints (no OIDC config found)", file=sys.stderr)

    # Step 2: Generate PKCE pair
    print("[*] Step 2: Generating PKCE pair...", file=sys.stderr)
    code_verifier, code_challenge = generate_pkce_pair()
    print(f"    code_verifier: {code_verifier[:20]}...", file=sys.stderr)
    print(f"    code_challenge: {code_challenge[:20]}...", file=sys.stderr)

    # Step 3: Initiate authorization request
    print("[*] Step 3: Initiating authorization request...", file=sys.stderr)
    state = secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    auth_params = {
        "client_id": args.client_id,
        "redirect_uri": args.redirect_uri,
        "response_type": "code",
        "scope": args.scope,
        "state": state,
        "nonce": nonce,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    # Follow redirects to get to the login form (but capture the page)
    resp = session.get(auth_endpoint, params=auth_params, allow_redirects=True)

    if resp.status_code != 200:
        print(f"[-] Auth endpoint returned {resp.status_code}", file=sys.stderr)
        print(f"    URL: {resp.url}", file=sys.stderr)
        if resp.text:
            print(f"    Body (first 500 chars): {resp.text[:500]}", file=sys.stderr)
        sys.exit(1)

    # Step 4: Parse login form
    print("[*] Step 4: Parsing login form...", file=sys.stderr)
    form_action = extract_form_action(resp.text)
    if not form_action:
        print("[-] Could not find login form action URL", file=sys.stderr)
        print(f"    Response URL: {resp.url}", file=sys.stderr)
        print(
            "    The login page may be JavaScript-rendered. Try browser-auth.py instead.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Make form_action absolute if relative
    if form_action.startswith("/"):
        parsed = urllib.parse.urlparse(resp.url)
        form_action = f"{parsed.scheme}://{parsed.netloc}{form_action}"

    hidden_fields = extract_hidden_fields(resp.text)
    username_field = detect_username_field(resp.text)
    password_field = detect_password_field(resp.text)

    print(f"    Form action: {form_action[:80]}...", file=sys.stderr)
    print(f"    Username field: {username_field}", file=sys.stderr)
    print(f"    Password field: {password_field}", file=sys.stderr)
    print(f"    Hidden fields: {list(hidden_fields.keys())}", file=sys.stderr)

    # Step 5: Submit credentials
    print("[*] Step 5: Submitting credentials...", file=sys.stderr)
    login_data = {
        username_field: args.username,
        password_field: args.password,
        **hidden_fields,
    }

    # Don't follow the redirect to the callback — we need the auth code from Location
    resp = session.post(form_action, data=login_data, allow_redirects=False)

    # Follow redirects manually until we hit the callback URI
    max_redirects = 15
    auth_code = None
    for i in range(max_redirects):
        if resp.status_code not in (301, 302, 303, 307, 308):
            # Check if we got an error page (wrong credentials, etc.)
            if resp.status_code == 200 and "error" in resp.text.lower():
                # Check for common error indicators
                if any(
                    err in resp.text.lower()
                    for err in [
                        "invalid credentials",
                        "invalid username",
                        "invalid password",
                        "account is disabled",
                        "account locked",
                    ]
                ):
                    print("[-] Authentication failed: invalid credentials", file=sys.stderr)
                    sys.exit(1)
            break

        location = resp.headers.get("Location", "")

        # Check if this is the callback with the auth code
        if args.redirect_uri.rstrip("/") in location:
            parsed = urllib.parse.urlparse(location)
            params = urllib.parse.parse_qs(parsed.query)

            # Check for error
            if "error" in params:
                print(
                    f"[-] Auth error: {params.get('error', ['?'])[0]} - "
                    f"{params.get('error_description', ['?'])[0]}",
                    file=sys.stderr,
                )
                sys.exit(1)

            auth_code = params.get("code", [None])[0]
            returned_state = params.get("state", [None])[0]

            if auth_code:
                print(f"    Authorization code: {auth_code[:20]}...", file=sys.stderr)
                if returned_state != state:
                    print(
                        f"    WARNING: State mismatch (sent={state[:10]}..., "
                        f"got={returned_state[:10] if returned_state else 'None'}...)",
                        file=sys.stderr,
                    )
                break

        # Make absolute if relative
        if location.startswith("/"):
            parsed_resp = urllib.parse.urlparse(resp.url)
            location = f"{parsed_resp.scheme}://{parsed_resp.netloc}{location}"

        print(f"    Redirect {i + 1}: {location[:80]}...", file=sys.stderr)
        resp = session.get(location, allow_redirects=False)

    if not auth_code:
        print("[-] Failed to capture authorization code", file=sys.stderr)
        print(f"    Last status: {resp.status_code}", file=sys.stderr)
        print(f"    Last URL: {resp.url}", file=sys.stderr)
        if resp.text and len(resp.text) < 1000:
            print(f"    Response: {resp.text}", file=sys.stderr)
        sys.exit(1)

    # Step 6: Exchange code for tokens
    print("[*] Step 6: Exchanging code for tokens...", file=sys.stderr)
    token_data = {
        "grant_type": "authorization_code",
        "client_id": args.client_id,
        "code": auth_code,
        "redirect_uri": args.redirect_uri,
        "code_verifier": code_verifier,
    }

    resp = session.post(token_endpoint, data=token_data)
    if resp.status_code != 200:
        print(f"[-] Token exchange failed: {resp.status_code}", file=sys.stderr)
        print(f"    Response: {resp.text[:500]}", file=sys.stderr)
        sys.exit(1)

    tokens = resp.json()
    access_token = tokens.get("access_token")
    refresh_token = tokens.get("refresh_token")
    id_token = tokens.get("id_token")

    if not access_token:
        print("[-] No access_token in response", file=sys.stderr)
        print(f"    Response keys: {list(tokens.keys())}", file=sys.stderr)
        sys.exit(1)

    print("[+] Authentication successful!", file=sys.stderr)
    print(f"    Token type: {tokens.get('token_type', 'unknown')}", file=sys.stderr)
    print(f"    Expires in: {tokens.get('expires_in', 'unknown')}s", file=sys.stderr)
    if tokens.get("scope"):
        print(f"    Scope: {tokens['scope']}", file=sys.stderr)

    # Save cookie jar if specified
    if args.cookie_jar and hasattr(session.cookies, "save"):
        session.cookies.save(ignore_discard=True, ignore_expires=True)
        print(f"    Cookies saved to: {args.cookie_jar}", file=sys.stderr)

    # Output based on format
    if args.output_format == "json":
        output = {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "id_token": id_token,
            "token_type": tokens.get("token_type", "Bearer"),
            "expires_in": tokens.get("expires_in"),
            "scope": tokens.get("scope"),
        }
        print(json.dumps(output, indent=2))
    elif args.output_format == "token":
        print(access_token)
    elif args.output_format == "cookie":
        print(f"Authorization: Bearer {access_token}")
    elif args.output_format == "both":
        print(f"ACCESS_TOKEN={access_token}")
        if refresh_token:
            print(f"REFRESH_TOKEN={refresh_token}")
        if id_token:
            print(f"ID_TOKEN={id_token}")


if __name__ == "__main__":
    main()
