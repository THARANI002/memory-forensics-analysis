# Deploying to Streamlit Community Cloud

This repo is ready to deploy as-is. Steps:

## 1. Push this repo to GitHub

```bash
cd memory_forensics-main
git remote add origin https://github.com/<your-username>/<your-repo>.git
git branch -M main
git push -u origin main
```

(This folder is already a git repo with everything committed — you just need
to create an empty repo on GitHub first at https://github.com/new, **without**
initializing it with a README/.gitignore/license, then run the commands above
with your repo's URL.)

## 2. Deploy on Streamlit Community Cloud

1. Go to https://share.streamlit.io and sign in with GitHub.
2. Click **"New app"**.
3. Pick your repository, branch (`main`), and set the main file path to `app.py`.
4. Click **"Advanced settings"** before deploying and explicitly select **Python 3.11 or 3.12**.
   Community Cloud has a known current bug where a `runtime.txt` file is
   sometimes ignored and the newest Python (3.13/3.14) is used instead, which
   can break packages like `volatility3`, `yara-python`, and `mitreattack-python`
   that don't yet have wheels for those versions. Picking the version explicitly
   in this dialog is the reliable way to control it right now (it can't be
   changed later without deleting and redeploying the app).
5. Click **Deploy**. First build takes a few minutes (this app has some
   heavier dependencies: `volatility3`, `yara-python`, `stix2`, `mitreattack-python`).

## 3. If a package fails to build

Community Cloud runs on a minimal Debian image. If `yara-python` ever fails
to build from source (uncommon — it ships prebuilt wheels for most platforms),
add a `packages.txt` file to the repo root with:

```
libyara-dev
```

Community Cloud installs anything listed there via `apt-get` before running
`pip install -r requirements.txt`.

## 4. Secrets (optional)

If you want to enable the VirusTotal / MISP / OTX threat-intel lookups, don't
commit a `.env` file. Instead, in the app's Streamlit Cloud dashboard go to
**Settings → Secrets** and paste:

```toml
VT_API_KEY = "..."
MISP_URL = "..."
MISP_API_KEY = "..."
OTX_API_KEY = "..."
```

The app works fully in demo mode with no secrets configured at all.

## 5. Resource limits to know about

Community Cloud's free tier gives each app about 1 GB RAM. This is fine for:
- Demo mode (no real memory dump needed)
- Small `.raw`/`.zip` uploads used for YARA/static scanning

It is **not** enough to run Volatility 3 against a real multi-GB memory dump —
that needs the self-hosted/Docker deployment described in `docs/DEPLOYMENT.md`
instead. `maxUploadSize` is capped at 500 MB in `.streamlit/config.toml` to
keep this realistic for the free tier; raise it if you deploy somewhere with
more resources.
