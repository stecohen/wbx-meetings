# wbx-meeting-transcripts

Simple script to list Webex meetings and export available transcripts.

## Setup

```bash
cd /Users/stcohen/projects/wbx-meeting-transcripts
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Set authentication (choose one):

You can start from the example file:

```bash
cp .env.example .env
```

The script auto-loads `.env` from the project root when it starts.

Option 1: Personal access token (existing behavior)

```bash
export WEBEX_ACCESS_TOKEN="your_token_here"
```

Option 2: OAuth in browser (recommended for longer-term use)

```bash
export WEBEX_CLIENT_ID="your_integration_client_id"
export WEBEX_CLIENT_SECRET="your_integration_client_secret"
export WEBEX_REDIRECT_PORT="8765" # optional if WEBEX_REDIRECT_URI is unset
export WEBEX_REDIRECT_URI="http://localhost:${WEBEX_REDIRECT_PORT}/callback"
export WEBEX_OAUTH_SCOPES="meeting:schedules_read meeting:recordings_read meeting:transcripts_read spark:people_read"
```

On first run, the script opens/prints an authorization URL.
After you approve in browser, tokens are cached in:

```bash
~/.wbx_meeting_transcripts_token.json
```

The script will auto-refresh tokens when possible.

## Run

```bash
python list-transcripts.py
python list-transcripts.py --days 7
python list-transcripts.py --csv
python list-transcripts.py --months 2 --csv
python list-transcripts.py --login
python list-transcripts.py --clear-auth
python list-transcripts.py --new-meetings --meetings-only
```

`--new-meetings` uses a local cache file at `~/.wbx_meeting_transcripts_seen_meetings.json` to track already-listed meeting IDs across runs.
