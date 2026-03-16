
#!/usr/bin/env python3
import argparse
import csv
import json
import os
import re
import sys
import secrets
import requests
import webbrowser
from pathlib import Path
from datetime import datetime, timedelta, timezone
from urllib.parse import urlencode, urlparse, parse_qs
from http.server import BaseHTTPRequestHandler, HTTPServer

# Constants
API_BASE = "https://webexapis.com/v1"
MEETINGS_ENDPOINT = f"{API_BASE}/meetings"
TRANSCRIPTS_ENDPOINT = f"{API_BASE}/meetingTranscripts"
AUTHORIZE_ENDPOINT = f"{API_BASE}/authorize"
TOKEN_ENDPOINT = f"{API_BASE}/access_token"
TOKEN_CACHE_PATH = Path.home() / ".wbx_meeting_transcripts_token.json"
SEEN_MEETINGS_CACHE_PATH = Path.home() / ".wbx_meeting_transcripts_seen_meetings.json"
PROJECT_ENV_PATH = Path(__file__).resolve().parent / ".env"
TOKEN_EXPIRY_SKEW_SECONDS = 60

_ACCESS_TOKEN_CACHE = None
_ACCESS_TOKEN_SOURCE = None


def load_env_file(path=PROJECT_ENV_PATH, override=False):
    """Load KEY=VALUE pairs from .env into process environment."""
    warnings = []
    if not path.exists():
        return False, warnings

    try:
        with open(path, "r", encoding="utf-8") as f:
            for index, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    warnings.append(
                        f"Warning: Ignoring malformed .env line {index} in {path}: {raw_line.strip()}"
                    )
                    continue

                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip()
                if not key:
                    warnings.append(
                        f"Warning: Ignoring .env line {index} with empty key in {path}"
                    )
                    continue

                if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                    value = value[1:-1]

                if not override and key in os.environ:
                    continue
                os.environ[key] = value
    except OSError as e:
        warnings.append(f"Warning: Could not read {path}: {e}")
        return False, warnings

    return True, warnings


def debug_log(enabled, message):
    """Print debug line when --debug is enabled."""
    if enabled:
        print(f"[DEBUG] {message}")


def debug_request(method, url, headers, params=None):
    """Print a safe debug view of the outbound request."""
    req = requests.Request(method=method, url=url, headers=headers, params=params)
    prepared = req.prepare()
    safe_headers = dict(prepared.headers)
    if "Authorization" in safe_headers:
        safe_headers["Authorization"] = "Bearer ***REDACTED***"
    print(f"[DEBUG] {prepared.method} {prepared.url}")
    print(f"[DEBUG] Headers: {safe_headers}")

def load_cached_oauth_token():
    """Load OAuth token cache from disk, if present."""
    if not TOKEN_CACHE_PATH.exists():
        return None
    try:
        with open(TOKEN_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError):
        return None
    return None


def load_seen_meeting_ids():
    """Load set of previously seen meeting IDs from disk."""
    if not SEEN_MEETINGS_CACHE_PATH.exists():
        return set()
    try:
        with open(SEEN_MEETINGS_CACHE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return set()
    if not isinstance(data, dict):
        return set()
    ids = data.get("meeting_ids", [])
    if not isinstance(ids, list):
        return set()
    return {item for item in ids if isinstance(item, str) and item}


def save_seen_meeting_ids(meeting_ids):
    """Persist seen meeting IDs to disk."""
    payload = {
        "meeting_ids": sorted(meeting_ids),
        "updated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    with open(SEEN_MEETINGS_CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.chmod(SEEN_MEETINGS_CACHE_PATH, 0o600)


def clear_auth_state():
    """Clear in-process token env vars and remove OAuth token cache file."""
    auth_env_keys = ["WEBEX_ACCESS_TOKEN"]
    cleared_keys = []
    for key in auth_env_keys:
        if key in os.environ:
            os.environ.pop(key, None)
            cleared_keys.append(key)

    cache_deleted = False
    cache_error = None
    if TOKEN_CACHE_PATH.exists():
        try:
            TOKEN_CACHE_PATH.unlink()
            cache_deleted = True
        except OSError as e:
            cache_error = str(e)

    return cleared_keys, cache_deleted, cache_error


def clear_auth_from_env_file(path=PROJECT_ENV_PATH):
    """Blank token keys in .env so they do not auto-load on next run."""
    auth_env_keys = {"WEBEX_ACCESS_TOKEN"}
    if not path.exists():
        return False, 0, None

    try:
        changed = 0
        new_lines = []
        with open(path, "r", encoding="utf-8") as f:
            for raw_line in f:
                stripped = raw_line.strip()
                if not stripped or stripped.startswith("#") or "=" not in raw_line:
                    new_lines.append(raw_line)
                    continue

                key, _ = raw_line.split("=", 1)
                key = key.strip()
                if key in auth_env_keys:
                    new_lines.append(f'{key}=""\n')
                    changed += 1
                else:
                    new_lines.append(raw_line)

        with open(path, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    except OSError as e:
        return True, 0, str(e)

    return True, changed, None


def save_cached_oauth_token(token_data):
    """Persist OAuth token cache to disk with restrictive permissions."""
    payload = dict(token_data)
    expires_in = payload.get("expires_in")
    if expires_in is not None and "expires_at" not in payload:
        try:
            payload["expires_at"] = int(datetime.now(timezone.utc).timestamp()) + int(expires_in)
        except (TypeError, ValueError):
            pass
    with open(TOKEN_CACHE_PATH, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    os.chmod(TOKEN_CACHE_PATH, 0o600)


def token_is_valid(token_data):
    """Check if cached token is still valid."""
    access_token = token_data.get("access_token")
    expires_at = token_data.get("expires_at")
    if not access_token:
        return False
    if not isinstance(expires_at, int):
        return False
    now_epoch = int(datetime.now(timezone.utc).timestamp())
    return now_epoch < (expires_at - TOKEN_EXPIRY_SKEW_SECONDS)


def exchange_token(payload, debug=False):
    """Exchange authorization code/refresh token for an access token."""
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    safe_payload = dict(payload)
    for key in ("client_secret", "refresh_token", "code"):
        if key in safe_payload:
            safe_payload[key] = "***REDACTED***"
    debug_log(debug, f"POST {TOKEN_ENDPOINT} payload={safe_payload}")
    response = requests.post(TOKEN_ENDPOINT, headers=headers, data=payload)
    debug_log(debug, f"token endpoint status: {response.status_code}")
    if response.status_code != 200:
        print(f"Error retrieving OAuth token: {response.status_code} - {response.text}", file=sys.stderr)
        return None
    data = response.json()
    if "expires_in" in data and "expires_at" not in data:
        try:
            data["expires_at"] = int(datetime.now(timezone.utc).timestamp()) + int(data["expires_in"])
        except (TypeError, ValueError):
            pass
    save_cached_oauth_token(data)
    return data


def refresh_oauth_token(client_id, client_secret, refresh_token, debug=False):
    """Refresh an OAuth token using refresh_token grant."""
    payload = {
        "grant_type": "refresh_token",
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
    }
    return exchange_token(payload, debug=debug)


class OAuthCallbackHandler(BaseHTTPRequestHandler):
    """One-shot local callback receiver for OAuth authorization code."""

    authorization_code = None
    state = None
    error = None

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        OAuthCallbackHandler.authorization_code = query.get("code", [None])[0]
        OAuthCallbackHandler.state = query.get("state", [None])[0]
        OAuthCallbackHandler.error = query.get("error", [None])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"<html><body><h3>Authorization received.</h3>You can close this window.</body></html>")

    def log_message(self, format_str, *args):
        return


def get_authorization_code(client_id, redirect_uri, scopes, debug=False):
    """Launch browser OAuth flow and retrieve authorization code."""
    state = secrets.token_urlsafe(24)
    auth_url = f"{AUTHORIZE_ENDPOINT}?{urlencode({'client_id': client_id, 'response_type': 'code', 'redirect_uri': redirect_uri, 'scope': scopes, 'state': state})}"

    parsed_redirect = urlparse(redirect_uri)
    local_hosts = {"localhost", "127.0.0.1"}
    callback_supported = parsed_redirect.scheme == "http" and parsed_redirect.hostname in local_hosts and parsed_redirect.port

    debug_log(debug, f"oauth redirect_uri={redirect_uri}")
    debug_log(debug, f"oauth scopes={scopes}")
    print("\nOpen this URL in your browser to authorize:\n")
    print(auth_url)
    print("")

    if callback_supported:
        OAuthCallbackHandler.authorization_code = None
        OAuthCallbackHandler.state = None
        OAuthCallbackHandler.error = None
        server = HTTPServer((parsed_redirect.hostname, parsed_redirect.port), OAuthCallbackHandler)
        server.timeout = 300
        try:
            webbrowser.open(auth_url)
        except Exception:
            pass

        print(f"Waiting for OAuth callback on {redirect_uri} ...")
        while OAuthCallbackHandler.authorization_code is None and OAuthCallbackHandler.error is None:
            server.handle_request()

        if OAuthCallbackHandler.error:
            print(f"OAuth error: {OAuthCallbackHandler.error}", file=sys.stderr)
            return None
        if OAuthCallbackHandler.state != state:
            print("OAuth state mismatch. Aborting.", file=sys.stderr)
            return None
        return OAuthCallbackHandler.authorization_code

    code = input("Paste the `code` parameter from the redirect URL: ").strip()
    return code or None


def oauth_access_token(debug=False):
    """Get access token via OAuth (with cache + refresh)."""
    client_id = os.environ.get("WEBEX_CLIENT_ID")
    client_secret = os.environ.get("WEBEX_CLIENT_SECRET")
    redirect_port = (os.environ.get("WEBEX_REDIRECT_PORT") or "8765").strip()
    redirect_uri = os.environ.get("WEBEX_REDIRECT_URI", f"http://localhost:{redirect_port}/callback")
    scopes = os.environ.get(
        "WEBEX_OAUTH_SCOPES",
        "meeting:schedules_read meeting:recordings_read meeting:transcripts_read spark:people_read",
    )

    if not client_id or not client_secret:
        print(
            "Warning: Missing OAuth configuration.",
            file=sys.stderr,
        )
        print(
            "Error: WEBEX_ACCESS_TOKEN is not set, and OAuth is not configured.\n"
            "Set WEBEX_CLIENT_ID and WEBEX_CLIENT_SECRET (and optionally WEBEX_REDIRECT_URI/"
            "WEBEX_REDIRECT_PORT/WEBEX_OAUTH_SCOPES).\n"
            "Tip: copy .env.example to .env and fill in values.",
            file=sys.stderr,
        )
        sys.exit(1)

    cached = load_cached_oauth_token()
    if cached and token_is_valid(cached):
        expires_at = cached.get("expires_at")
        debug_log(debug, f"using cached OAuth access token from {TOKEN_CACHE_PATH} (expires_at={expires_at})")
        return cached.get("access_token")

    if cached and cached.get("refresh_token"):
        debug_log(debug, f"cached token present but expired; attempting refresh from {TOKEN_CACHE_PATH}")
        refreshed = refresh_oauth_token(client_id, client_secret, cached["refresh_token"], debug=debug)
        if refreshed and refreshed.get("access_token"):
            debug_log(debug, "refresh succeeded")
            return refreshed["access_token"]
        debug_log(debug, "refresh failed; falling back to browser authorization code flow")

    code = get_authorization_code(client_id, redirect_uri, scopes, debug=debug)
    if not code:
        print("Could not obtain OAuth authorization code.", file=sys.stderr)
        sys.exit(1)

    token_data = exchange_token({
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }, debug=debug)
    if not token_data or not token_data.get("access_token"):
        print("Failed to obtain OAuth access token.", file=sys.stderr)
        sys.exit(1)
    return token_data["access_token"]


def get_access_token(debug=False):
    """Get access token from env var or OAuth."""
    global _ACCESS_TOKEN_CACHE, _ACCESS_TOKEN_SOURCE
    if _ACCESS_TOKEN_CACHE:
        debug_log(debug, "using in-memory access token cache")
        _ACCESS_TOKEN_SOURCE = "in_memory"
        return _ACCESS_TOKEN_CACHE

    token = os.environ.get("WEBEX_ACCESS_TOKEN")
    if token:
        debug_log(debug, "using WEBEX_ACCESS_TOKEN from environment")
        _ACCESS_TOKEN_CACHE = token
        _ACCESS_TOKEN_SOURCE = "env"
        return token

    debug_log(debug, "WEBEX_ACCESS_TOKEN not set; using OAuth flow")
    _ACCESS_TOKEN_CACHE = oauth_access_token(debug=debug)
    _ACCESS_TOKEN_SOURCE = "oauth"
    return _ACCESS_TOKEN_CACHE


def get_headers(debug=False):
    """Build auth headers for Webex API calls."""
    return {
        "Authorization": f"Bearer {get_access_token(debug=debug)}",
        "Content-Type": "application/json"
    }


def sanitize_filename(value):
    """Convert a string to a filesystem-safe filename stem."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value or "")
    cleaned = cleaned.strip("._")
    return cleaned or "transcript"


def build_transcript_filename(meeting_title, meeting_start, meeting_id):
    """Build default transcript filename from title and meeting date."""
    meeting_date = None
    if meeting_start:
        try:
            dt_obj = datetime.fromisoformat(meeting_start.replace('Z', '+00:00'))
            meeting_date = dt_obj.strftime("%Y-%m-%d")
        except ValueError:
            meeting_date = None

    filename_stem = sanitize_filename(meeting_title) if meeting_title else sanitize_filename(meeting_id)
    if meeting_date:
        filename_stem = f"{filename_stem}_{meeting_date}"
    return f"{filename_stem}.txt"


def get_unique_output_path(directory, filename):
    """Avoid overwriting files by adding a numeric suffix when needed."""
    base_name, ext = os.path.splitext(filename)
    candidate = os.path.join(directory, filename)
    counter = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, f"{base_name}_{counter}{ext}")
        counter += 1
    return candidate


def get_meeting_details(meeting_id, debug=False):
    """Fetch meeting details by meeting ID."""
    headers = get_headers(debug=debug)
    url = f"{MEETINGS_ENDPOINT}/{meeting_id}"
    try:
        if debug:
            debug_request("GET", url, headers)
        response = requests.get(url, headers=headers)
        if debug:
            print(f"[DEBUG] meeting details status: {response.status_code}")
            print(f"[DEBUG] meeting details body: {response.text}")
        if response.status_code != 200:
            return None
        data = response.json()
        return data
    except Exception:
        return None

def list_meetings(start_date, end_date, debug=False):
    """Fetch all meetings within the date range."""
    headers = get_headers(debug=debug)
    params = {
        "from": start_date.isoformat(timespec="seconds"),
        "to": end_date.isoformat(timespec="seconds"),
        "max": 100,
        "meetingType": "meeting",  # Filters for completed meetings typically
        "hasTranscription": True,
        "state": "ended"
    }
    
    meetings = []
    url = MEETINGS_ENDPOINT
    
    while url:
        if debug:
            debug_request("GET", url, headers, params=params)
        response = requests.get(url, headers=headers, params=params)
        if response.status_code != 200:
            tracking_id = response.headers.get("trackingid") or response.headers.get("Trackingid") or response.headers.get("trackingId")
            debug_log(debug, f"meetings API failed status={response.status_code} trackingId={tracking_id}")
            print(f"Error fetching meetings: {response.status_code} - {response.text}", file=sys.stderr)
            break
            
        data = response.json()
        meetings.extend(data.get("items", []))
        
        # Handle pagination
        url = None
        if "Link" in response.headers:
            links = response.headers["Link"].split(",")
            for link in links:
                if 'rel="next"' in link:
                    url = link.split(";")[0].strip("<> ")
                    params = {} # Params are usually included in the next link
                    break
    return meetings

def get_transcript(meeting_id, debug=False):
    """Fetch transcript text for a meeting via vttDownloadLink."""
    headers = get_headers(debug=debug)
    params = {"meetingId": meeting_id}
    
    try:
        if debug:
            debug_request("GET", TRANSCRIPTS_ENDPOINT, headers, params=params)
        response = requests.get(TRANSCRIPTS_ENDPOINT, headers=headers, params=params)
        if debug:
            print(f"[DEBUG] meetingTranscripts status: {response.status_code}")
            print(f"[DEBUG] meetingTranscripts body: {response.text}")
        
        if response.status_code == 404:
            return None # No transcript found
        if response.status_code != 200:
            tracking_id = response.headers.get("trackingid") or response.headers.get("Trackingid") or response.headers.get("trackingId")
            debug_log(debug, f"meetingTranscripts API failed status={response.status_code} trackingId={tracking_id}")
            # print(f"Debug: Failed to get transcript for {meeting_id}: {response.status_code}", file=sys.stderr)
            return None

        data = response.json()
        items = data.get("items", [])
        if not items:
            return None

        vtt_link = None
        for item in items:
            if item.get("vttDownloadLink"):
                vtt_link = item.get("vttDownloadLink")
                break

        if not vtt_link:
            if debug:
                print("[DEBUG] No vttDownloadLink found in meetingTranscripts response.")
            return None

        if debug:
            debug_request("GET", vtt_link, headers)
        vtt_response = requests.get(vtt_link, headers=headers)
        if debug:
            print(f"[DEBUG] transcript download status: {vtt_response.status_code}")

        if vtt_response.status_code != 200:
            if debug:
                print(f"[DEBUG] transcript download body: {vtt_response.text}")
            return None

        transcript_text = vtt_response.text.strip()
        return transcript_text or None
        
    except Exception as e:
        print(f"Error retrieving transcript: {e}", file=sys.stderr)
        return None

def main():
    _, env_warnings = load_env_file()
    for warning in env_warnings:
        print(warning, file=sys.stderr)

    parser = argparse.ArgumentParser(
        prog="wbx-meeting-transcripts",
        description="List and extract Webex meeting transcripts."
    )
    
    parser.add_argument(
        "-m", "--months",
        type=int,
        default=0,
        help="Number of previous months to retrieve (used when --days is not set). e.g., -m 2 for last 60 days."
    )
    parser.add_argument(
        "-d", "--days",
        type=int,
        help="Number of previous days to retrieve (overrides --months and default 30 days)."
    )
    
    parser.add_argument(
        "-c", "--csv",
        action="store_true",
        help="Create a .csv file with all details (date, title, id, transcript)."
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print outbound Webex request details (URL, query params, redacted auth header)."
    )
    parser.add_argument(
        "--meetings-only",
        action="store_true",
        help="List meeting details only without querying meeting transcripts."
    )
    parser.add_argument(
        "--meeting-id",
        help="Download transcript for a specific meeting ID and skip list mode."
    )
    parser.add_argument(
        "--filter",
        help="Case-insensitive title filter for listing meetings (e.g., --filter matt)."
    )
    parser.add_argument(
        "--new-meetings",
        action="store_true",
        help="List only meetings not seen in earlier runs (tracked by local meeting ID cache)."
    )
    parser.add_argument(
        "--output",
        help="Output file path for --meeting-id (defaults to <meeting_title>.txt)."
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="In list mode, also download each transcript to a text file."
    )
    parser.add_argument(
        "--download-dir",
        default=".",
        help="Directory for --download transcript files (default: current directory)."
    )
    parser.add_argument(
        "--login",
        action="store_true",
        help="Authenticate via OAuth (or refresh cached OAuth token) and exit."
    )
    parser.add_argument(
        "--clear-auth",
        action="store_true",
        help="Clear token auth (WEBEX_ACCESS_TOKEN and local OAuth token cache), then exit."
    )
    
    args = parser.parse_args()

    if args.output and not args.meeting_id:
        print("Error: --output can only be used with --meeting-id.", file=sys.stderr)
        sys.exit(1)
        
    if args.meetings_only and args.download:
        print("Error: --download cannot be used with --meetings-only.", file=sys.stderr)
        sys.exit(1)
    if args.days is not None and args.days <= 0:
        print("Error: --days must be greater than 0.", file=sys.stderr)
        sys.exit(1)

    if args.clear_auth:
        cleared_keys, cache_deleted, cache_error = clear_auth_state()
        env_file_exists, env_file_changes, env_file_error = clear_auth_from_env_file()
        if cleared_keys:
            print(f"Cleared in-process auth vars: {', '.join(cleared_keys)}")
        else:
            print("No in-process Webex auth vars were set.")

        if cache_deleted:
            print(f"Deleted OAuth token cache: {TOKEN_CACHE_PATH}")
        elif cache_error:
            print(f"Warning: Could not delete token cache {TOKEN_CACHE_PATH}: {cache_error}", file=sys.stderr)
        else:
            print(f"No OAuth token cache found at: {TOKEN_CACHE_PATH}")

        if env_file_exists and env_file_changes > 0:
            print(f'Cleared {env_file_changes} auth entries in: {PROJECT_ENV_PATH}')
        elif env_file_error:
            print(f"Warning: Could not update {PROJECT_ENV_PATH}: {env_file_error}", file=sys.stderr)
        elif env_file_exists:
            print(f"No auth entries found to clear in: {PROJECT_ENV_PATH}")
        else:
            print(f"No .env file found at: {PROJECT_ENV_PATH}")

        print(
            "Note: to clear variables from your current shell session, run:\n"
            "unset WEBEX_ACCESS_TOKEN"
        )
        return

    if args.login:
        # Triggers OAuth/browser flow or refresh path, then exits without transcript queries.
        _ = get_access_token(debug=args.debug)
        if _ACCESS_TOKEN_SOURCE == "oauth":
            print(f"Authentication successful via OAuth. Token cache: {TOKEN_CACHE_PATH}")
        elif _ACCESS_TOKEN_SOURCE == "env":
            print("Authentication successful via WEBEX_ACCESS_TOKEN from environment.")
        else:
            print("Authentication successful.")
        return

    if args.meeting_id:
        transcript_text = get_transcript(args.meeting_id, debug=args.debug)
        if not transcript_text:
            print(f"No transcript found for meeting ID: {args.meeting_id}")
            return

        output_path = args.output
        if not output_path:
            meeting_details = get_meeting_details(args.meeting_id, debug=args.debug)
            meeting_title = meeting_details.get("title") if meeting_details else None
            meeting_start = meeting_details.get("start") if meeting_details else None
            output_path = build_transcript_filename(meeting_title, meeting_start, args.meeting_id)

        try:
            with open(output_path, mode="w", encoding="utf-8") as f:
                f.write(transcript_text)
            print(f"Transcript downloaded to {output_path}")
        except IOError as e:
            print(f"Error writing transcript file: {e}", file=sys.stderr)
            sys.exit(1)
        return

    # Calculate Date Range
    end_date = datetime.now(timezone.utc)
    
    if args.days is not None:
        days_back = args.days
    elif args.months > 0:
        days_back = args.months * 30
    else:
        days_back = 30 # Default
        
    start_date = end_date - timedelta(days=days_back)
    
    print(f"Searching for transcripts from {start_date.date()} to {end_date.date()}...")

    if args.download:
        os.makedirs(args.download_dir, exist_ok=True)

    meetings = list_meetings(start_date, end_date, debug=args.debug)

    if args.filter:
        query = args.filter.lower()
        meetings = [m for m in meetings if query in (m.get("title", "") or "").lower()]

    if args.new_meetings:
        seen_ids = load_seen_meeting_ids()
        original_count = len(meetings)
        meetings = [m for m in meetings if (m.get("id") or "") not in seen_ids]
        debug_log(
            args.debug,
            f"new-meetings filter: {len(meetings)}/{original_count} unseen "
            f"(cache: {SEEN_MEETINGS_CACHE_PATH})",
        )
    
    if not meetings:
        if args.new_meetings and args.filter:
            print(f'No new meetings found in this period matching filter "{args.filter}".')
        elif args.new_meetings:
            print("No new meetings found in this period.")
        elif args.filter:
            print(f'No meetings found in this period matching filter "{args.filter}".')
        else:
            print("No meetings found in this period.")
        return

    results = []

    if args.meetings_only:
        print(f"\n{'Date':<12} | {'Title':<40} | {'Meeting ID'}")
    else:
        print(f"\n{'Date':<12} | {'Title'}")
    print("-" * 50)

    for meeting in meetings:
        title = meeting.get("title", "Untitled")
        start = meeting.get("start", "")
        m_id = meeting.get("id")
        
        # Format date for display
        try:
            dt_obj = datetime.fromisoformat(start.replace('Z', '+00:00'))
            date_str = dt_obj.strftime("%Y-%m-%d")
        except ValueError:
            date_str = start

        if args.meetings_only:
            print(f"{date_str:<12} | {title[:40]:<40} | {m_id}")
            results.append({
                "date": date_str,
                "title": title,
                "id": m_id
            })
            continue

        # Attempt to get transcript
        transcript_text = get_transcript(m_id, debug=args.debug)
        
        if transcript_text:
            print(f"{date_str:<12} | {title}")
            results.append({
                "date": date_str,
                "title": title,
                "id": m_id,
                "transcript": transcript_text
            })
            if args.download:
                filename = build_transcript_filename(title, start, m_id)
                output_path = get_unique_output_path(args.download_dir, filename)
                try:
                    with open(output_path, mode="w", encoding="utf-8") as f:
                        f.write(transcript_text)
                    print(f"  Downloaded: {output_path}")
                except IOError as e:
                    print(f"Error writing transcript file for meeting {m_id}: {e}", file=sys.stderr)
        # Note: We silently skip meetings without transcripts to avoid cluttering stdout

    # CSV Export
    if args.csv:
        if results:
            filename = f"transcripts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            try:
                with open(filename, mode='w', newline='', encoding='utf-8') as f:
                    fieldnames = ["date", "title", "id", "transcript"]
                    if args.meetings_only:
                        fieldnames = ["date", "title", "id"]
                    writer = csv.DictWriter(f, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(results)
                item_type = "meetings" if args.meetings_only else "transcripts"
                print(f"\nSuccessfully created {filename} with {len(results)} {item_type}.")
            except IOError as e:
                print(f"Error writing CSV: {e}", file=sys.stderr)
        else:
            print("\nNo transcripts found to export.")

    if args.new_meetings:
        existing_seen_ids = load_seen_meeting_ids()
        new_ids = {(m.get("id") or "") for m in meetings if m.get("id")}
        if new_ids:
            save_seen_meeting_ids(existing_seen_ids | new_ids)
            print(
                f"\nRecorded {len(new_ids)} meeting IDs in cache: {SEEN_MEETINGS_CACHE_PATH}"
            )

if __name__ == "__main__":
    main()
