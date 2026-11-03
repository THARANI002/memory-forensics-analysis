"""
Design system
=============
One place for every visual decision: tokens (light + dark), typography,
motion, component CSS, inline SVG icons and small HTML component builders.

Principles: generous space, one accent colour, hairline borders, soft layered
shadows, spring easing, motion that respects `prefers-reduced-motion`, and
real semantics (headings, tables, aria labels) so it stays accessible.
"""
from __future__ import annotations

import html as _html
from typing import Callable, Dict, Iterable, List, Optional, Sequence

import streamlit as st

__all__ = [
    "inject_theme", "resolved_mode", "icon", "md", "esc", "Raw", "hero", "page_header", "section",
    "stat_card", "stat_grid", "score_ring", "badge", "sev_tone", "card", "finding_card", "empty_state",
    "feature_card", "feature_grid", "steps", "data_table", "style_figure", "kv", "tone_hex", "chip",
]

# --------------------------------------------------------------------------- tokens
LIGHT = {
    "bg": "#f5f5f7", "surface": "#ffffff", "surface2": "#f2f2f7", "surface3": "#e8e8ed",
    "line": "rgba(0,0,0,.08)", "line2": "rgba(0,0,0,.14)",
    "text": "#1d1d1f", "text2": "#6e6e73", "text3": "#86868b",
    "blue": "#0071e3", "blue2": "#0077ed", "green": "#248a3d", "orange": "#b25000",
    "yellow": "#8a6d00", "red": "#d70015", "teal": "#0a7f9d", "purple": "#8944ab",
    "blue_f": "#0071e3", "green_f": "#34c759", "orange_f": "#ff9500", "yellow_f": "#ffcc00",
    "red_f": "#ff3b30", "teal_f": "#5ac8fa", "purple_f": "#af52de",
    "shadow1": "0 1px 2px rgba(0,0,0,.04), 0 2px 8px rgba(0,0,0,.04)",
    "shadow2": "0 2px 6px rgba(0,0,0,.06), 0 12px 32px rgba(0,0,0,.10)",
    "glass": "rgba(255,255,255,.72)", "scheme": "light",
}
DARK = {
    "bg": "#000000", "surface": "#1c1c1e", "surface2": "#2c2c2e", "surface3": "#3a3a3c",
    "line": "rgba(255,255,255,.10)", "line2": "rgba(255,255,255,.18)",
    "text": "#f5f5f7", "text2": "#a1a1a6", "text3": "#8e8e93",
    "blue": "#2997ff", "blue2": "#0a84ff", "green": "#30d158", "orange": "#ff9f0a",
    "yellow": "#ffd60a", "red": "#ff453a", "teal": "#64d2ff", "purple": "#bf5af2",
    "blue_f": "#0a84ff", "green_f": "#30d158", "orange_f": "#ff9f0a", "yellow_f": "#ffd60a",
    "red_f": "#ff453a", "teal_f": "#64d2ff", "purple_f": "#bf5af2",
    "shadow1": "0 1px 0 rgba(255,255,255,.04) inset, 0 2px 10px rgba(0,0,0,.5)",
    "shadow2": "0 1px 0 rgba(255,255,255,.06) inset, 0 16px 40px rgba(0,0,0,.65)",
    "glass": "rgba(28,28,30,.72)", "scheme": "dark",
}


def _vars(p: Dict[str, str]) -> str:
    return ";".join(f"--{k.replace('_', '-')}:{v}" for k, v in p.items())


def resolved_mode() -> str:
    """'light' or 'dark' after applying the user's Appearance choice."""
    choice = st.session_state.get("appearance", "Auto")
    if choice == "Light":
        return "light"
    if choice == "Dark":
        return "dark"
    try:
        t = st.context.theme.type
        if t in ("light", "dark"):
            return t
    except Exception:
        pass
    return "dark"


def tone_hex(tone: str, text: bool = False) -> str:
    p = LIGHT if resolved_mode() == "light" else DARK
    key = {"critical": "red", "high": "orange", "medium": "yellow", "low": "green", "info": "blue",
           "ok": "green", "neutral": "text2"}.get(tone, tone)
    return p.get(key if text or key == "text2" else key + "_f", p["text2"])


# --------------------------------------------------------------------------- icons
_ICONS = {
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/>',
    "radar": '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/>',
    "search": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    "fingerprint": '<path d="M12 11a3 3 0 0 0-3 3c0 2.5-.5 4.5-1.5 6.5"/><path d="M12 7a7 7 0 0 0-7 7c0 2-.3 3.6-.8 5"/><path d="M12 3a11 11 0 0 1 11 11c0 1.7-.2 3.2-.5 4.5"/><path d="M15 14c0 3-.5 5.2-1.5 7.5"/><path d="M8 4.6A11 11 0 0 0 1 14"/>',
    "grid": '<rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    "clock": '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    "file": '<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5z"/><path d="M14 2v6h6M16 13H8M16 17H8"/>',
    "activity": '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    "layers": '<path d="m12 2 10 5-10 5L2 7z"/><path d="m2 17 10 5 10-5M2 12l10 5 10-5"/>',
    "compare": '<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M12 3v18"/>',
    "alert": '<path d="m21.7 18-8-14a2 2 0 0 0-3.4 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3z"/><path d="M12 9v4M12 17h.01"/>',
    "check": '<circle cx="12" cy="12" r="10"/><path d="m8 12 3 3 5-6"/>',
    "cpu": '<rect x="5" y="5" width="14" height="14" rx="2"/><rect x="9" y="9" width="6" height="6"/><path d="M9 1v4M15 1v4M9 19v4M15 19v4M1 9h4M1 15h4M19 9h4M19 15h4"/>',
    "upload": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m17 8-5-5-5 5M12 3v12"/>',
    "download": '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="m7 10 5 5 5-5M12 15V3"/>',
    "globe": '<circle cx="12" cy="12" r="10"/><path d="M2 12h20"/><path d="M12 2a15 15 0 0 1 0 20 15 15 0 0 1 0-20z"/>',
    "terminal": '<path d="m4 17 6-6-6-6M12 19h8"/>',
    "database": '<ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.7-4 3-9 3s-9-1.3-9-3"/><path d="M3 5v14c0 1.7 4 3 9 3s9-1.3 9-3V5"/>',
    "trend": '<path d="m22 7-8.5 8.5-5-5L2 17"/><path d="M16 7h6v6"/>',
    "lock": '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "sparkle": '<path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M18.4 5.6l-2.8 2.8M8.4 15.6l-2.8 2.8"/>',
    "box": '<path d="M21 8 12 3 3 8v8l9 5 9-5z"/><path d="m3 8 9 5 9-5M12 13v8"/>',
    "bug": '<rect x="8" y="6" width="8" height="14" rx="4"/><path d="M19 7l-3 2M5 7l3 2M19 19l-3-2M5 19l3-2M20 13h-4M4 13h4M10 2l1 2M14 2l-1 2"/>',
    "flag": '<path d="M4 22V4M4 4h13l-2 4 2 4H4"/>',
    "play": '<path d="M7 4v16l13-8z"/>',
}


def icon(name: str, size: int = 20, label: Optional[str] = None, stroke: float = 1.75) -> str:
    body = _ICONS.get(name, _ICONS["sparkle"])
    a11y = f'role="img" aria-label="{esc(label)}"' if label else 'aria-hidden="true" focusable="false"'
    return (f'<svg class="ico" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="{stroke}" stroke-linecap="round" stroke-linejoin="round" {a11y}>{body}</svg>')


# --------------------------------------------------------------------------- helpers
class Raw(str):
    """Marks a string as already-safe HTML for data_table cells."""


def esc(x) -> str:
    return _html.escape("" if x is None else str(x))


def _flat(s: str) -> str:
    """Collapse to one line: Markdown would otherwise treat indented/blank lines as code or end the HTML block."""
    return "".join(line.strip() for line in s.splitlines())


def md(s: str) -> None:
    st.markdown(_flat(s), unsafe_allow_html=True)


# --------------------------------------------------------------------------- CSS
_CSS = r"""
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
:root{
  --font:-apple-system,BlinkMacSystemFont,"SF Pro Display","SF Pro Text",Inter,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,"SF Mono",SFMono-Regular,Menlo,Consolas,monospace;
  --r-sm:10px;--r-md:14px;--r-lg:20px;--r-xl:28px;
  --spring:cubic-bezier(.34,1.56,.64,1);--ease:cubic-bezier(.22,.61,.36,1);
}
html,body,.stApp,button,input,textarea,select{font-family:var(--font)!important;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}
.stApp{background:var(--bg);color:var(--text);color-scheme:var(--scheme)}
.stApp,.stApp p,.stApp li,.stApp label,.stApp span,.stApp div[data-testid="stMarkdownContainer"],.stApp [data-testid="stWidgetLabel"]{color:var(--text)}
.stApp [data-testid="stCaptionContainer"],.stApp small{color:var(--text2)!important}
a{color:var(--blue);text-decoration:none}a:hover{text-decoration:underline}
::selection{background:var(--blue);color:#fff}

/* layout */
[data-testid="stHeader"]{background:transparent;height:0;min-height:0}
[data-testid="stToolbar"],[data-testid="stDecoration"],#MainMenu,footer{display:none!important}
[data-testid="stMainBlockContainer"]{max-width:1180px;padding:3.2rem 2rem 5rem}
[data-testid="stSidebarCollapsedControl"] button,[data-testid="stSidebarCollapseButton"] button{color:var(--text2)}
h1,h2,h3,h4{font-family:var(--font)!important;color:var(--text)!important;letter-spacing:-.022em;font-weight:600}
hr{border:none!important;border-top:1px solid var(--line)!important;margin:1.6rem 0!important}
*:focus-visible{outline:3px solid color-mix(in srgb,var(--blue) 55%,transparent)!important;outline-offset:2px;border-radius:8px}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}

.card h4,.step h4,.feat h4,.finding h4,.empty h4,.page-head h2,.sec h3,.hero h1{padding:0!important}
.page-head p,.sec span{margin-bottom:0!important}
.page-head h2{margin:0!important}.page-head p{margin:.25rem 0 0!important}
[data-baseweb="input"]>div,[data-baseweb="base-input"],[data-baseweb="select"]>div>div{background:transparent!important}
[data-baseweb="input"],[data-baseweb="select"]>div{border:1px solid var(--line2)!important;background:var(--surface)!important}
input::placeholder,textarea::placeholder{color:var(--text3)!important;opacity:1}
/* motion */
@keyframes rise{from{opacity:0;transform:translateY(14px) scale(.985)}to{opacity:1;transform:none}}
@keyframes fade{from{opacity:0}to{opacity:1}}
@keyframes ring{from{stroke-dashoffset:var(--circ)}to{stroke-dashoffset:var(--off)}}
@keyframes pulse{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--dot) 55%,transparent)}70%{box-shadow:0 0 0 9px transparent}100%{box-shadow:0 0 0 0 transparent}}
@keyframes floaty{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.rise{animation:rise .7s var(--spring) both;animation-delay:calc(var(--i,0) * 70ms)}

/* brand + hero */
.brand{display:flex;align-items:center;gap:.7rem;margin:.2rem 0 1.2rem}
.brand-mark{width:38px;height:38px;border-radius:11px;display:grid;place-items:center;color:#fff;
  background:linear-gradient(145deg,#2997ff,#0a5ed7 60%,#5e5ce6);box-shadow:0 6px 16px rgba(10,94,215,.35)}
.brand-name{font-weight:650;font-size:1.02rem;letter-spacing:-.02em;line-height:1.1}
.brand-sub{font-size:.74rem;color:var(--text2)!important;margin-top:2px}
.hero{position:relative;text-align:center;padding:4.2rem 1rem 3rem;overflow:hidden;border-radius:var(--r-xl)}
.hero:before{content:"";position:absolute;inset:-30% -10% auto;height:120%;z-index:0;pointer-events:none;
  background:radial-gradient(60% 55% at 30% 30%,color-mix(in srgb,var(--blue-f) 22%,transparent),transparent 70%),
             radial-gradient(50% 50% at 75% 25%,color-mix(in srgb,var(--purple-f) 20%,transparent),transparent 70%),
             radial-gradient(45% 45% at 55% 70%,color-mix(in srgb,var(--teal-f) 14%,transparent),transparent 70%);filter:blur(10px)}
.hero>*{position:relative;z-index:1}
.eyebrow{display:inline-flex;align-items:center;gap:.45rem;font-size:.82rem;font-weight:600;color:var(--blue)!important;
  background:color-mix(in srgb,var(--blue) 10%,transparent);padding:.35rem .8rem;border-radius:980px;letter-spacing:.01em}
.hero h1{font-size:clamp(2.4rem,6.2vw,4.6rem);line-height:1.04;font-weight:700;letter-spacing:-.045em;margin:1.1rem auto .9rem;max-width:17ch}
.grad{background:linear-gradient(100deg,#0a84ff 0%,#5e5ce6 45%,#bf5af2 100%);-webkit-background-clip:text;background-clip:text;color:transparent!important;-webkit-text-fill-color:transparent}
.hero p.lead{font-size:clamp(1.05rem,1.8vw,1.3rem);line-height:1.45;color:var(--text2)!important;max-width:36rem;margin:0 auto 1.6rem;letter-spacing:-.011em}
.page-head{display:flex;align-items:center;gap:.9rem;margin:.2rem 0 1.5rem}
.page-head .pi{width:44px;height:44px;border-radius:13px;display:grid;place-items:center;color:var(--blue);
  background:color-mix(in srgb,var(--blue) 11%,transparent)}
.page-head h2{margin:0!important;font-size:1.9rem;line-height:1.1;letter-spacing:-.03em}
.page-head p{margin:.2rem 0 0;color:var(--text2)!important;font-size:.98rem}
.sec{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:.2rem 1rem;margin:2.2rem 0 .9rem}
.sec h3{margin:0!important;font-size:1.28rem;letter-spacing:-.02em}
.sec span.sub{color:var(--text2)!important;font-size:.9rem}

/* cards */
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--r-lg);padding:1.35rem 1.4rem;box-shadow:var(--shadow1);
  transition:transform .45s var(--spring),box-shadow .3s var(--ease),border-color .3s var(--ease)}
.card.hov:hover{transform:translateY(-4px);box-shadow:var(--shadow2);border-color:var(--line2)}
.grid{display:grid;gap:1rem}
.g4{grid-template-columns:repeat(4,minmax(0,1fr))}.g3{grid-template-columns:repeat(3,minmax(0,1fr))}.g2{grid-template-columns:repeat(2,minmax(0,1fr))}
.stat{display:flex;flex-direction:column;gap:.35rem;position:relative;overflow:hidden}
.stat .lbl{display:flex;align-items:center;gap:.45rem;font-size:.78rem;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text2)!important}
.stat .val{font-size:2.5rem;font-weight:650;letter-spacing:-.04em;line-height:1.05;font-variant-numeric:tabular-nums}
.stat .hint{font-size:.82rem;color:var(--text2)!important}
.feat .fi{width:46px;height:46px;border-radius:14px;display:grid;place-items:center;margin-bottom:.9rem;color:#fff;background:var(--tone)}
.feat h4{margin:0 0 .35rem!important;font-size:1.08rem}.feat p{margin:0;color:var(--text2)!important;font-size:.93rem;line-height:1.5}
.step{display:flex;gap:1rem;align-items:flex-start}
.step .n{flex:none;width:34px;height:34px;border-radius:50%;display:grid;place-items:center;font-weight:650;color:var(--blue);
  background:color-mix(in srgb,var(--blue) 12%,transparent)}
.step h4{margin:.1rem 0 .2rem!important;font-size:1rem}.step p{margin:0;color:var(--text2)!important;font-size:.9rem}

/* verdict ring */
.ringwrap{display:flex;flex-direction:column;align-items:center;gap:.9rem;text-align:center}
.ringbox{position:relative;width:190px;height:190px}
.ringbox svg{transform:rotate(-90deg);overflow:visible}
.ringbox .trk{stroke:var(--surface3)}
.ringbox .arc{stroke-dasharray:var(--circ);stroke-dashoffset:var(--off);animation:ring 1.4s var(--ease) both;filter:drop-shadow(0 0 8px color-mix(in srgb,var(--tone) 55%,transparent))}
.ringbox.crit .arc{animation:ring 1.4s var(--ease) both,glowpulse 2.6s 1.4s infinite}
.ringbox .mid{position:absolute;inset:0;display:grid;place-content:center;text-align:center}
.ringbox .num{font-size:3.1rem;font-weight:700;letter-spacing:-.05em;line-height:1}
.ringbox .of{font-size:.78rem;color:var(--text2)!important;margin-top:.2rem}

/* badges, chips, findings */
.badge{display:inline-flex;align-items:center;gap:.4rem;font-size:.74rem;font-weight:650;letter-spacing:.03em;text-transform:uppercase;
  padding:.28rem .65rem;border-radius:980px;color:var(--tone-t)!important;background:color-mix(in srgb,var(--tone) 14%,transparent)}
.badge:before{content:"";width:6px;height:6px;border-radius:50%;background:var(--tone)}
.chip{display:inline-flex;align-items:center;gap:.35rem;font-size:.8rem;padding:.3rem .7rem;border-radius:980px;background:var(--surface2);color:var(--text2)!important;border:1px solid var(--line)}
.finding{display:flex;gap:1rem;align-items:flex-start;padding:1.05rem 1.2rem;margin-bottom:.65rem;position:relative;overflow:hidden}
.finding:before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--tone)}
.finding h4{margin:0 0 .25rem!important;font-size:1.02rem}.finding p{margin:0;color:var(--text2)!important;font-size:.9rem;line-height:1.45}
.finding .meta{display:flex;gap:.4rem;flex-wrap:wrap;margin-top:.6rem}
.empty{text-align:center;padding:3.2rem 1.5rem}
.empty .ei{width:64px;height:64px;border-radius:20px;margin:0 auto 1rem;display:grid;place-items:center;color:var(--text2);background:var(--surface2)}
.empty h4{margin:0 0 .35rem!important;font-size:1.15rem}.empty p{margin:0 auto;color:var(--text2)!important;max-width:30rem;font-size:.95rem}
.kv{display:grid;grid-template-columns:auto 1fr;gap:.55rem 1.2rem;margin:0}
.kv dt{color:var(--text2);font-size:.85rem}.kv dd{margin:0;font-weight:550;word-break:break-word}
.status{display:inline-flex;align-items:center;gap:.55rem;font-size:.88rem;font-weight:550;padding:.5rem .9rem;border-radius:980px;
  background:color-mix(in srgb,var(--dot) 12%,transparent);color:var(--text)!important;width:100%}
.status i{width:8px;height:8px;border-radius:50%;background:var(--dot);animation:pulse 2.2s infinite}
.snap{font-size:.82rem;padding:.7rem .85rem;border-radius:var(--r-md);background:var(--surface2);margin-bottom:.45rem}
.snap b{display:block;font-weight:600}.snap span{color:var(--text2)!important;font-family:var(--mono);font-size:.74rem}

/* tables */
.tbl-wrap{overflow:auto;border:1px solid var(--line);border-radius:var(--r-lg);background:var(--surface);max-height:520px;box-shadow:var(--shadow1)}
.tbl{width:100%;border-collapse:separate;border-spacing:0;font-size:.88rem}
.tbl caption{position:absolute;left:-9999px}
.tbl th{position:sticky;top:0;text-align:left;font-weight:600;font-size:.74rem;text-transform:uppercase;letter-spacing:.06em;color:var(--text2);
  background:var(--glass);backdrop-filter:blur(14px) saturate(1.6);-webkit-backdrop-filter:blur(14px) saturate(1.6);padding:.8rem 1rem;border-bottom:1px solid var(--line);white-space:nowrap}
.tbl td{padding:.72rem 1rem;border-bottom:1px solid var(--line);vertical-align:top;color:var(--text)}
.tbl tr:last-child td{border-bottom:none}.tbl tbody tr{transition:background .2s var(--ease)}.tbl tbody tr:hover{background:var(--surface2)}
.tbl th,.tbl td{border-left:0!important;border-right:0!important;border-top:0!important}
.tbl td.mono{font-family:var(--mono);font-size:.82rem;word-break:break-all}
.tbl-foot{font-size:.8rem;color:var(--text2);margin:.5rem .3rem 0}

/* Streamlit widgets */
.stButton>button,.stDownloadButton>button,[data-testid="stBaseButton-secondary"],[data-testid="stBaseButton-primary"]{
  border-radius:980px!important;font-weight:550;padding:.5rem 1.25rem;border:1px solid var(--line2)!important;background:var(--surface)!important;color:var(--text)!important;
  box-shadow:var(--shadow1);transition:transform .35s var(--spring),box-shadow .25s var(--ease),background .2s var(--ease)}
.stButton>button:hover,.stDownloadButton>button:hover{transform:translateY(-1px) scale(1.02);box-shadow:var(--shadow2)}
.stButton>button:active,.stDownloadButton>button:active{transform:scale(.96)}
.stButton>button[kind="primary"],[data-testid="stBaseButton-primary"]{background:linear-gradient(180deg,#2997ff,#0071e3)!important;color:#fff!important;border-color:transparent!important;
  box-shadow:0 6px 18px rgba(0,113,227,.38)}
.stButton>button[kind="primary"] *,[data-testid="stBaseButton-primary"] *{color:#fff!important}
.stButton>button[kind="primary"]:hover{box-shadow:0 10px 26px rgba(0,113,227,.5)}
[data-testid="stSidebar"]{background:var(--glass)!important;backdrop-filter:blur(24px) saturate(1.8);-webkit-backdrop-filter:blur(24px) saturate(1.8);border-right:1px solid var(--line)}
[data-testid="stSidebar"] [data-testid="stSidebarUserContent"]{padding-top:1.4rem}
[data-testid="stSidebar"] h3{font-size:.74rem!important;text-transform:uppercase;letter-spacing:.08em;color:var(--text2)!important;font-weight:650;margin:1.3rem 0 .5rem}
[data-testid="stFileUploaderDropzone"]{background:var(--surface);border:1.5px dashed var(--line2);border-radius:var(--r-lg);transition:border-color .25s,background .25s}
[data-testid="stFileUploaderDropzone"]:hover{border-color:var(--blue);background:color-mix(in srgb,var(--blue) 5%,var(--surface))}
[data-testid="stFileUploaderDropzone"] *{color:var(--text2)!important}
[data-baseweb="select"]>div,[data-baseweb="input"],[data-baseweb="base-input"],textarea,input{background:var(--surface)!important;color:var(--text)!important;border-color:var(--line2)!important;border-radius:var(--r-md)!important}
[data-baseweb="select"] *{color:var(--text)!important}
[data-baseweb="popover"] *,[data-baseweb="menu"]{background:var(--surface)!important;color:var(--text)!important}
[data-baseweb="tag"]{background:color-mix(in srgb,var(--blue) 16%,transparent)!important;border-radius:980px!important}
[data-testid="stExpander"]{background:var(--surface);border:1px solid var(--line)!important;border-radius:var(--r-lg);box-shadow:var(--shadow1);overflow:hidden}
[data-testid="stExpander"] summary:hover{background:var(--surface2)}
[data-testid="stAlert"]{border-radius:var(--r-md);border:1px solid var(--line);background:var(--surface)}
[data-testid="stAlert"] *{color:var(--text)!important}
[data-testid="stTabs"] [role="tablist"]{gap:.3rem;border-bottom:1px solid var(--line)}
[data-testid="stTabs"] button[role="tab"]{border-radius:10px 10px 0 0;color:var(--text2)}
[data-testid="stTabs"] button[aria-selected="true"]{color:var(--text)}
[data-testid="stSlider"] [role="slider"]{background:var(--blue)!important}
[data-testid="stJson"],.stJson{border-radius:var(--r-md)}
code{font-family:var(--mono)!important;background:var(--surface2)!important;color:var(--text)!important;border-radius:6px}

/* primary navigation (segmented control) */
[data-testid="stButtonGroup"] [role="radiogroup"]{display:flex;flex-wrap:nowrap!important;gap:2px;padding:4px;border-radius:14px;background:var(--surface2);
  border:1px solid var(--line);width:fit-content;max-width:100%;overflow-x:auto;scrollbar-width:none;margin-bottom:.4rem}
[data-testid="stButtonGroup"] [role="radiogroup"]::-webkit-scrollbar{display:none}
[data-testid="stButtonGroup"] button[role="radio"]{flex:none;border:none!important;border-radius:11px!important;background:transparent!important;color:var(--text2)!important;
  padding:.5rem .95rem;white-space:nowrap;font-weight:550;box-shadow:none;transition:background .3s var(--ease),color .2s,transform .35s var(--spring)}
[data-testid="stButtonGroup"] button[role="radio"] *{color:inherit!important}
[data-testid="stButtonGroup"] button[role="radio"]:hover{color:var(--text)!important;transform:translateY(-1px)}
[data-testid="stButtonGroup"] button[role="radio"][aria-checked="true"]{background:var(--surface)!important;color:var(--text)!important;box-shadow:var(--shadow1),0 0 0 1px var(--line)}
.stSpinner,[data-testid="stSpinner"]{color:var(--text2)}

.card p{color:var(--text2);line-height:1.6;margin:.2rem 0 0}.card h4{margin:0 0 .4rem!important;font-size:1.05rem}
.meter{display:flex;align-items:center;gap:.55rem;min-width:110px}.meter b{font-variant-numeric:tabular-nums;font-weight:600;width:2.6rem}
.meter i{flex:1;height:6px;border-radius:6px;background:var(--surface3);overflow:hidden;position:relative}
.meter i:after{content:"";position:absolute;inset:0;width:var(--w);background:var(--tone);border-radius:6px;transform-origin:left;animation:grow .9s var(--ease) both}
@keyframes grow{from{transform:scaleX(0)}to{transform:scaleX(1)}}
.reclist{margin:0;padding:0;list-style:none;display:grid;gap:.7rem}
.reclist li{display:flex;gap:.8rem;align-items:flex-start;font-size:.93rem;line-height:1.45}
.reclist li span{flex:none;width:26px;height:26px;border-radius:50%;display:grid;place-items:center;font-size:.8rem;font-weight:650;color:var(--blue);background:color-mix(in srgb,var(--blue) 12%,transparent)}

/* ===== dynamic layer ===== */
@property --n{syntax:"<integer>";initial-value:0;inherits:false}
@property --ang{syntax:"<angle>";initial-value:0deg;inherits:false}
@keyframes count{from{--n:0}to{--n:var(--to)}}
@keyframes spin{to{--ang:360deg}}
@keyframes drift{0%{transform:translate3d(-4%,-3%,0) scale(1)}50%{transform:translate3d(5%,4%,0) scale(1.12)}100%{transform:translate3d(-2%,6%,0) scale(1.04)}}
@keyframes drift2{0%{transform:translate3d(6%,2%,0) scale(1.1)}100%{transform:translate3d(-6%,-5%,0) scale(.95)}}
@keyframes rotw{0%{opacity:0;transform:translateY(.45em) scale(.96);filter:blur(8px)}5%,21%{opacity:1;transform:none;filter:none}26%,100%{opacity:0;transform:translateY(-.45em) scale(.98);filter:blur(8px)}}
@keyframes sheen{0%{transform:translateX(-130%) skewX(-18deg)}60%,100%{transform:translateX(230%) skewX(-18deg)}}
@keyframes lineIn{from{opacity:0;transform:translateX(-14px)}to{opacity:1;transform:none}}
@keyframes scan{0%{top:-20%}100%{top:120%}}
@keyframes glowpulse{0%,100%{filter:drop-shadow(0 0 6px color-mix(in srgb,var(--tone) 45%,transparent))}50%{filter:drop-shadow(0 0 20px color-mix(in srgb,var(--tone) 85%,transparent))}}
@keyframes blink{50%{opacity:.25}}
@keyframes growx{from{transform:scaleX(0)}to{transform:scaleX(1)}}
@keyframes popin{0%{transform:scale(.4);opacity:0}70%{transform:scale(1.15)}100%{transform:scale(1);opacity:1}}

/* living background */
[data-testid="stMain"]{position:relative;z-index:1}
.stApp:before,.stApp:after{content:"";position:fixed;z-index:0;pointer-events:none;border-radius:50%;filter:blur(70px);opacity:var(--aurora)}
.stApp:before{width:62vw;height:62vw;left:-14vw;top:-22vw;background:radial-gradient(circle,var(--blue-f),transparent 65%);animation:drift 26s ease-in-out infinite alternate}
.stApp:after{width:52vw;height:52vw;right:-12vw;bottom:-20vw;background:radial-gradient(circle,var(--purple-f),transparent 65%);animation:drift2 32s ease-in-out infinite alternate}
:root{--aurora:.13}
@media (prefers-color-scheme:dark){:root{--aurora:.20}}

/* count-up numbers */
.cnt{display:inline-block;animation:count 1.4s var(--ease) both;counter-reset:n var(--n);font-variant-numeric:tabular-nums}
.cnt:after{content:counter(n)}.cnt.pct:after{content:counter(n) "%"}

/* animated conic glow border on hover */
.card.hov{position:relative}
.card.hov:after{content:"";position:absolute;inset:-1px;border-radius:inherit;padding:1.5px;pointer-events:none;opacity:0;transition:opacity .4s var(--ease);
  background:conic-gradient(from var(--ang),transparent 0 62%,var(--tone,var(--blue-f)) 82%,transparent 100%);
  -webkit-mask:linear-gradient(#000 0 0) content-box,linear-gradient(#000 0 0);-webkit-mask-composite:xor;mask:linear-gradient(#000 0 0) content-box exclude,linear-gradient(#000 0 0);
  animation:spin 3.2s linear infinite}
.card.hov:hover:after{opacity:1}
.stat:before{content:"";position:absolute;right:-30px;top:-30px;width:110px;height:110px;border-radius:50%;
  background:radial-gradient(circle,color-mix(in srgb,var(--tone) 22%,transparent),transparent 70%);pointer-events:none;transition:transform .6s var(--spring)}
.stat:hover:before{transform:scale(1.5)}
.feat .fi{transition:transform .5s var(--spring)}.feat:hover .fi{transform:rotate(-8deg) scale(1.12)}

/* sticky glass navigation */
[data-testid="stMain"] [data-testid="stElementContainer"]:has(> [data-testid="stButtonGroup"]){position:sticky;top:0;z-index:70;padding:.7rem 0 .5rem;margin:-.7rem 0 .3rem;
  background:linear-gradient(to bottom,color-mix(in srgb,var(--bg) 88%,transparent) 62%,transparent);backdrop-filter:blur(14px) saturate(1.5);-webkit-backdrop-filter:blur(14px) saturate(1.5)}
[data-testid="stButtonGroup"] button[role="radio"] .ico{transition:transform .45s var(--spring)}
[data-testid="stButtonGroup"] button[role="radio"][aria-checked="true"] [data-testid="stIconMaterial"]{color:var(--blue)!important}

/* primary button sheen */
.stButton>button[kind="primary"]{position:relative;overflow:hidden}
.stButton>button[kind="primary"]:after{content:"";position:absolute;top:0;bottom:0;width:38%;left:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.38),transparent);animation:sheen 4.2s ease-in-out infinite}

/* hero extras */
.rot{display:inline-grid;vertical-align:bottom;text-align:center}
.rot>span{grid-area:1/1;opacity:0;animation:rotw 12s infinite both;background:linear-gradient(100deg,#0a84ff 0%,#5e5ce6 45%,#bf5af2 100%);-webkit-background-clip:text;background-clip:text;color:transparent;-webkit-text-fill-color:transparent}
.rot>span:nth-child(2){animation-delay:3s}.rot>span:nth-child(3){animation-delay:6s}.rot>span:nth-child(4){animation-delay:9s}
.hero .badges{display:flex;gap:.5rem;justify-content:center;flex-wrap:wrap;margin-top:1.1rem}

/* terminal / live feed */
.term{position:relative;overflow:hidden;border-radius:var(--r-xl);border:1px solid var(--line2);background:color-mix(in srgb,var(--surface) 82%,transparent);
  backdrop-filter:blur(18px);-webkit-backdrop-filter:blur(18px);box-shadow:var(--shadow2);max-width:880px;margin:1.6rem auto 0;text-align:left}
.term-bar{display:flex;align-items:center;gap:.4rem;padding:.75rem 1rem;border-bottom:1px solid var(--line);background:var(--surface2)}
.term-bar i{width:11px;height:11px;border-radius:50%;display:inline-block}
.term-bar i:nth-child(1){background:#ff5f57}.term-bar i:nth-child(2){background:#febc2e}.term-bar i:nth-child(3){background:#28c840}
.term-bar span{margin-left:.6rem;font-size:.78rem;color:var(--text2);font-family:var(--mono)}
.term-bar .live{margin-left:auto;display:inline-flex;align-items:center;gap:.4rem;color:var(--green)!important;font-weight:600}
.term-bar .live:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--green-f);animation:blink 1.4s infinite}
.term-body{position:relative;padding:.6rem 1rem 1rem;display:grid;gap:.15rem}
.term-body:after{content:"";position:absolute;left:0;right:0;height:22%;top:-20%;pointer-events:none;
  background:linear-gradient(to bottom,transparent,color-mix(in srgb,var(--blue-f) 12%,transparent),transparent);animation:scan 5s linear infinite}
.tline{display:grid;grid-template-columns:auto 1fr auto;gap:.8rem;align-items:center;padding:.5rem .4rem;border-radius:10px;font-size:.86rem;
  opacity:0;animation:lineIn .6s var(--spring) both;animation-delay:calc(var(--i) * 260ms + 500ms)}
.tline:hover{background:var(--surface2)}
.tline .t{font-family:var(--mono);font-size:.78rem;color:var(--text2)}
.tline b{font-weight:600}.tline .p{font-family:var(--mono);font-size:.78rem;color:var(--text2);white-space:nowrap}

/* severity bar */
.sevbar{display:flex;height:16px;border-radius:99px;overflow:hidden;background:var(--surface3);gap:3px}
.sevbar i{display:block;background:var(--tone);flex:var(--n) 1 0;min-width:0;transform-origin:left;animation:growx 1.1s var(--ease) both;animation-delay:calc(var(--i)*120ms)}
.sevleg{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.8rem;margin-top:1.2rem}
.sevleg div{display:flex;flex-direction:column;gap:.1rem}
.sevleg .k{display:flex;align-items:center;gap:.4rem;font-size:.78rem;color:var(--text2)!important;font-weight:600;text-transform:uppercase;letter-spacing:.05em}
.sevleg .k:before{content:"";width:9px;height:9px;border-radius:3px;background:var(--tone)}
.sevleg .v{font-size:1.9rem;font-weight:650;letter-spacing:-.03em;color:var(--tone-t)!important}
.sevleg .pc{font-size:.8rem;color:var(--text2)!important}

/* kill chain */
.kc{list-style:none;margin:0;padding:1.2rem 1rem 1rem;display:flex;overflow-x:auto;scrollbar-width:none}
.kc::-webkit-scrollbar{display:none}
.kc{-webkit-mask-image:linear-gradient(90deg,#000 92%,transparent);mask-image:linear-gradient(90deg,#000 92%,transparent)}
.kc li{flex:1 0 70px;display:flex;flex-direction:column;align-items:center;gap:.55rem;position:relative;text-align:center;padding:0 .2rem;
  opacity:0;animation:rise .6s var(--spring) both;animation-delay:calc(var(--i)*55ms)}
.kc li:not(:last-child):before{content:"";position:absolute;top:19px;left:50%;width:100%;height:3px;background:var(--surface3);border-radius:3px}
.kc li.done:not(:last-child):before{background:linear-gradient(90deg,var(--tone),var(--blue-f));transform-origin:left;animation:growx .8s var(--ease) both;animation-delay:calc(var(--i)*55ms + 300ms)}
.kc .d{position:relative;z-index:1;width:40px;height:40px;border-radius:50%;display:grid;place-items:center;font-weight:650;font-size:.85rem;
  background:var(--surface2);color:var(--text3)!important;border:2px solid var(--surface3);transition:transform .45s var(--spring)}
.kc li.on .d{background:var(--tone);color:#fff!important;border-color:transparent;box-shadow:0 6px 18px color-mix(in srgb,var(--tone) 50%,transparent);animation:glowpulse 2.6s infinite}
.kc li:hover .d{transform:scale(1.14)}
.kc .nm{font-size:.7rem;line-height:1.2;color:var(--text3)!important;font-weight:550;max-width:72px}
.kc li.on .nm{color:var(--text)!important}
.kc .ct{position:absolute;top:-6px;right:calc(50% - 30px);z-index:2;min-width:20px;height:20px;border-radius:99px;display:grid;place-items:center;font-size:.7rem;font-weight:700;
  background:var(--text);color:var(--bg)!important;animation:popin .6s var(--spring) both;animation-delay:calc(var(--i)*55ms + 600ms);padding:0 5px}

/* vertical timeline */
.tl{list-style:none;margin:0;padding:.2rem 0 .2rem 1.4rem;position:relative;max-height:620px;overflow:auto}
.tl:before{content:"";position:absolute;left:.62rem;top:.6rem;bottom:.6rem;width:2px;background:linear-gradient(var(--line2),transparent);border-radius:2px}
.tl li{position:relative;padding:.1rem 0 1.15rem 1.2rem;opacity:0;animation:lineIn .6s var(--spring) both;animation-delay:calc(var(--i)*45ms)}
.tl li:before{content:"";position:absolute;left:-1.1rem;top:.35rem;width:13px;height:13px;border-radius:50%;background:var(--tone);box-shadow:0 0 0 4px var(--surface),0 0 14px color-mix(in srgb,var(--tone) 60%,transparent)}
.tl .tm{font-family:var(--mono);font-size:.76rem;color:var(--text2)}
.tl .ti{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;margin:.15rem 0}
.tl .ti b{font-weight:600}.tl p{margin:.1rem 0 0;font-size:.88rem;color:var(--text2)!important}

/* process tree */
.pt{margin:0}.pt>summary,.pt.leaf{list-style:none;cursor:pointer}.pt>summary::-webkit-details-marker{display:none}
.pt-row{display:flex;align-items:center;gap:.6rem;flex-wrap:wrap;padding:.5rem .75rem;border-radius:12px;border:1px solid transparent;transition:background .25s var(--ease),border-color .25s,transform .35s var(--spring)}
.pt-row:hover{background:var(--surface2);transform:translateX(3px)}
.pt-row .tw{width:16px;height:16px;flex:none;color:var(--text3);transition:transform .3s var(--spring)}
details.pt[open]>summary .tw{transform:rotate(90deg)}
.pt-row .nm{font-weight:600}.pt-row code{font-size:.74rem}
.pt-row.bad{background:color-mix(in srgb,var(--red-f) 9%,transparent);border-color:color-mix(in srgb,var(--red-f) 35%,transparent)}
.pt-row.bad .nm{color:var(--red)!important}
.pt-kids{margin-left:1.15rem;padding-left:.9rem;border-left:2px solid var(--line);display:grid;gap:.15rem;margin-top:.15rem}
.pt-detail{margin:.2rem 0 .5rem 2.1rem;font-size:.82rem;color:var(--text2)!important;font-family:var(--mono);word-break:break-all}
.pt-wrap{padding:1rem}

/* responsive */
@media (max-width:1000px){.g4{grid-template-columns:repeat(2,minmax(0,1fr))}.g3{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:640px){
  [data-testid="stSidebar"]{background:var(--surface)!important;backdrop-filter:none}
  [data-testid="stMainBlockContainer"]{padding:2rem 1rem 4rem}
  .g3{grid-template-columns:1fr}.g4,.g2{grid-template-columns:repeat(2,minmax(0,1fr))}.hero{padding:2.6rem .5rem 2rem}
  .stat .val{font-size:1.9rem}.card{padding:1.1rem 1rem}.stat .lbl{font-size:.68rem}
  .sevleg{grid-template-columns:repeat(2,minmax(0,1fr))}.tline{grid-template-columns:auto 1fr}.tline .p{display:none}
  .page-head h2{font-size:1.5rem}.ringbox{width:160px;height:160px}.ringbox .num{font-size:2.6rem}
}
@media (prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.001ms!important;animation-iteration-count:1!important;transition-duration:.001ms!important}}
@media (prefers-contrast:more){:root{--line:rgba(128,128,128,.55)}}
"""


def inject_theme() -> str:
    """Inject tokens + component CSS. Returns the resolved mode ('light'|'dark')."""
    choice = st.session_state.get("appearance", "Auto")
    light, dark = _vars(LIGHT), _vars(DARK)
    if choice == "Light":
        tokens = f":root{{{light}}}"
    elif choice == "Dark":
        tokens = f":root{{{dark}}}"
    else:
        tokens = f":root{{{light}}}@media (prefers-color-scheme:dark){{:root{{{dark}}}}}"
    # tone helpers consumed by components via style="--tone:..." resolved in CSS vars below
    st.markdown(f"<style>{tokens}{_CSS}</style>", unsafe_allow_html=True)
    return resolved_mode()


# --------------------------------------------------------------------------- components
_TONE_VAR = {"critical": "red", "high": "orange", "medium": "yellow", "low": "green", "info": "blue",
             "ok": "green", "neutral": "text2", "blue": "blue", "purple": "purple", "teal": "teal",
             "green": "green", "orange": "orange", "red": "red", "yellow": "yellow"}


def sev_tone(sev: str) -> str:
    s = (sev or "").lower()
    return {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
            "minimal": "ok", "clean": "ok"}.get(s, "neutral")


def _tone_style(tone: str) -> str:
    v = _TONE_VAR.get(tone, "text2")
    fill = f"var(--{v}-f)" if v not in ("text2",) else "var(--text2)"
    return f"--tone:{fill};--tone-t:var(--{v})"


def hero(eyebrow: str, headline_html: str, lead: str) -> str:
    return (f'<section class="hero rise"><span class="eyebrow">{icon("shield", 16)}{esc(eyebrow)}</span>'
            f'<h1>{headline_html}</h1><p class="lead">{esc(lead)}</p></section>')


def page_header(title: str, subtitle: str, icon_name: str = "grid") -> str:
    return (f'<header class="page-head rise"><div class="pi">{icon(icon_name, 22)}</div>'
            f'<div><h2>{esc(title)}</h2><p>{esc(subtitle)}</p></div></header>')


def section(title: str, sub: str = "") -> str:
    return f'<div class="sec"><h3>{esc(title)}</h3><span class="sub">{esc(sub)}</span></div>'


def badge(text: str, tone: str = "neutral") -> str:
    return f'<span class="badge" style="{_tone_style(tone)}">{esc(text)}</span>'


def chip(text: str, icon_name: Optional[str] = None) -> str:
    return f'<span class="chip">{icon(icon_name, 14) if icon_name else ""}{esc(text)}</span>'


def card(inner: str, interactive: bool = False, extra: str = "") -> str:
    return f'<div class="card{" hov" if interactive else ""}" {extra}>{inner}</div>'


def stat_card(label: str, value, tone: str = "blue", hint: str = "", icon_name: str = "activity", i: int = 0) -> str:
    return (f'<div class="card stat hov rise" style="{_tone_style(tone)};--i:{i}">'
            f'<div class="lbl">{icon(icon_name, 15)}{esc(label)}</div>'
            f'<div class="val" style="color:var(--tone-t)">{_num_html(value)}</div>'
            f'<div class="hint">{esc(hint) if hint else "&nbsp;"}</div></div>')


def stat_grid(cards: Iterable[str], cols: int = 4) -> str:
    return f'<div class="grid g{cols}">{"".join(cards)}</div>'


def score_ring(score: float, verdict: str, tone: str, caption: str = "Threat score") -> str:
    r = 80
    circ = 2 * 3.14159265 * r
    pct = max(0.0, min(float(score), 100.0)) / 100.0
    off = circ * (1 - pct)
    return (f'<div class="ringwrap rise"><div class="ringbox{' crit' if tone == 'critical' else ''}" style="{_tone_style(tone)}" role="img" '
            f'aria-label="{esc(caption)} {score:.0f} out of 100, verdict {esc(verdict)}">'
            f'<svg width="100%" height="100%" viewBox="0 0 190 190"><circle class="trk" cx="95" cy="95" r="{r}" fill="none" stroke-width="13"/>'
            f'<circle class="arc" cx="95" cy="95" r="{r}" fill="none" stroke="var(--tone)" stroke-width="13" stroke-linecap="round" '
            f'style="--circ:{circ:.1f};--off:{off:.1f}"/></svg>'
            f'<div class="mid"><div class="num" style="color:var(--tone-t)">{_num_html(f"{score:.0f}")}</div><div class="of">{esc(caption)} / 100</div></div></div>'
            f'{badge(verdict, tone)}</div>')


def finding_card(sev: str, title: str, desc: str, meta: Sequence[str] = (), i: int = 0) -> str:
    tone = sev_tone(sev)
    chips = "".join(meta)
    return (f'<article class="card finding hov rise" style="{_tone_style(tone)};--i:{min(i, 8)}"><div style="flex:1;min-width:0">'
            f'<div style="display:flex;gap:.6rem;align-items:center;flex-wrap:wrap;margin-bottom:.4rem">{badge(sev or "info", tone)}</div>'
            f'<h4>{esc(title)}</h4><p>{esc(desc)}</p>'
            f'{f"<div class=meta>{chips}</div>" if chips else ""}</div></article>')


def empty_state(icon_name: str, title: str, body: str) -> str:
    return (f'<div class="card empty rise"><div class="ei">{icon(icon_name, 28)}</div><h4>{esc(title)}</h4><p>{esc(body)}</p></div>')


def feature_card(icon_name: str, title: str, body: str, tone: str = "blue", i: int = 0) -> str:
    return (f'<div class="card feat hov rise" style="{_tone_style(tone)};--i:{i}"><div class="fi">{icon(icon_name, 22)}</div>'
            f'<h4>{esc(title)}</h4><p>{esc(body)}</p></div>')


def feature_grid(cards: Iterable[str], cols: int = 3) -> str:
    return f'<div class="grid g{cols}">{"".join(cards)}</div>'


def steps(items: Sequence[tuple]) -> str:
    rows = "".join(f'<div class="step rise" style="--i:{i}"><div class="n">{i + 1}</div><div><h4>{esc(t)}</h4><p>{esc(b)}</p></div></div>'
                   for i, (t, b) in enumerate(items))
    return f'<div class="card"><div class="grid g3">{rows}</div></div>'


def kv(rows: Sequence[tuple]) -> str:
    inner = "".join(f"<dt>{esc(k)}</dt><dd>{v if isinstance(v, Raw) else esc(v)}</dd>" for k, v in rows)
    return f'<dl class="kv">{inner}</dl>'


def data_table(rows: Sequence[Dict], columns: Optional[Sequence[str]] = None, caption: str = "Data table",
               max_rows: int = 400, mono: Sequence[str] = ()) -> str:
    """Semantic, responsive HTML table. Cell values wrapped in Raw() are not escaped."""
    rows = list(rows)
    if not rows:
        return empty_state("search", "Nothing to show", "No rows match the current view.")
    cols = list(columns or rows[0].keys())
    head = "".join(f'<th scope="col">{esc(c)}</th>' for c in cols)
    body = []
    for r in rows[:max_rows]:
        tds = []
        for c in cols:
            v = r.get(c, "")
            cell = v if isinstance(v, Raw) else esc(v)
            tds.append(f'<td class="{"mono" if c in mono else ""}">{cell}</td>')
        body.append(f'<tr>{"".join(tds)}</tr>')
    foot = f'<div class="tbl-foot">Showing {min(len(rows), max_rows)} of {len(rows)} rows</div>'
    return (f'<div class="tbl-wrap" tabindex="0" role="region" aria-label="{esc(caption)}">'
            f'<table class="tbl"><caption>{esc(caption)}</caption><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></div>{foot}')


def style_figure(fig, height: int = 320, legend: bool = False):
    """Apply the design system to a Plotly figure (transparent, hairline grid, system font)."""
    p = LIGHT if resolved_mode() == "light" else DARK
    fig.update_layout(
        height=height, margin=dict(l=8, r=8, t=12, b=8), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="-apple-system, BlinkMacSystemFont, 'SF Pro Text', Inter, Helvetica, Arial, sans-serif", color=p["text2"], size=12),
        showlegend=legend, legend=dict(orientation="h", y=1.08, font=dict(color=p["text2"])),
        colorway=[p["blue_f"], p["purple_f"], p["teal_f"], p["orange_f"], p["green_f"], p["red_f"]],
        hoverlabel=dict(bgcolor=p["surface"], bordercolor=p["line2"] if "rgba" not in p["line2"] else "#888", font=dict(color=p["text"])),
        coloraxis_showscale=False, transition=dict(duration=500, easing="cubic-in-out"),
    )
    grid = "rgba(128,128,128,.18)"
    fig.update_xaxes(gridcolor=grid, zeroline=False, linecolor=grid, tickfont=dict(color=p["text2"]), title_font=dict(color=p["text2"]))
    fig.update_yaxes(gridcolor=grid, zeroline=False, linecolor=grid, tickfont=dict(color=p["text2"]), title_font=dict(color=p["text2"]))
    return fig


# --------------------------------------------------------------------------- navigation
NAV = [
    ("overview", ":material/dashboard: Overview"),
    ("snapshots", ":material/compare: Snapshots"),
    ("hunter", ":material/radar: Threat hunter"),
    ("iocs", ":material/fingerprint: IOCs"),
    ("mitre", ":material/hub: ATT&CK"),
    ("processes", ":material/account_tree: Processes"),
    ("timeline", ":material/timeline: Timeline"),
    ("reports", ":material/description: Reports"),
    ("history", ":material/monitoring: History"),
]
NAV_LABEL = dict(NAV)
__all__ += ["NAV", "NAV_LABEL", "goto"]


def goto(page_key: str) -> Callable[[], None]:
    """on_click callback that switches the primary navigation to *page_key*."""
    def _cb() -> None:
        st.session_state["nav"] = NAV_LABEL[page_key]
    return _cb


# --------------------------------------------------------------------------- dynamic components
import re as _re


def _num_html(value) -> str:
    """Animated count-up for plain numbers/percentages; anything else is shown as text."""
    text = str(value)
    m = _re.fullmatch(r"(\d+(?:\.\d+)?)(%?)", text)
    if not m:
        return esc(text)
    n = int(round(float(m.group(1))))
    pct = " pct" if m.group(2) else ""
    return f'<span class="sr-only">{esc(text)}</span><span class="cnt{pct}" aria-hidden="true" style="--to:{n}"></span>'


def rotating_words(words: Sequence[str]) -> str:
    return '<span class="rot">' + "".join(f"<span>{esc(w)}</span>" for w in words[:4]) + "</span>"


def terminal_feed(title: str, rows: Sequence[tuple]) -> str:
    """rows: (severity, headline, detail, time). Real detections animate in line by line."""
    lines = "".join(
        f'<div class="tline" style="--i:{i};{_tone_style(sev_tone(sev))}">{badge(sev, sev_tone(sev))}'
        f'<span><b>{esc(head)}</b> <span class="t">{esc(tm)}</span></span><span class="p">{esc(detail)}</span></div>'
        for i, (sev, head, detail, tm) in enumerate(rows))
    return (f'<div class="term rise" role="img" aria-label="Preview of detections from the demo scenario">'
            f'<div class="term-bar"><i></i><i></i><i></i><span>{esc(title)}</span><span class="live">live analysis</span></div>'
            f'<div class="term-body">{lines}</div></div>')


def severity_bar(items: Sequence[tuple]) -> str:
    """items: (label, count, tone)."""
    total = sum(c for _, c, _ in items) or 1
    segs = "".join(f'<i style="{_tone_style(t)};--n:{c};--i:{i}" title="{esc(n)}: {c}"></i>'
                   for i, (n, c, t) in enumerate(items) if c)
    leg = "".join(f'<div style="{_tone_style(t)}"><span class="k">{esc(n)}</span>'
                  f'<span class="v">{_num_html(c)}</span><span class="pc">{c / total * 100:.0f}% of findings</span></div>'
                  for n, c, t in items)
    return (f'<div class="card rise"><div class="sevbar" role="img" aria-label="Severity distribution">{segs}</div>'
            f'<div class="sevleg">{leg}</div></div>')


def kill_chain(order: Sequence[str], counts: Dict[str, int], tone: str = "high") -> str:
    active = [i for i, t in enumerate(order) if counts.get(t)]
    last = max(active) if active else -1
    first = min(active) if active else 0
    items = []
    for i, t in enumerate(order):
        on = bool(counts.get(t))
        cls = "on" if on else ""
        if first <= i < last:
            cls += " done"
        badge_ct = f'<span class="ct">{counts[t]}</span>' if on else ""
        items.append(f'<li class="{cls.strip()}" style="--i:{i};{_tone_style(tone)}">{badge_ct}'
                     f'<span class="d">{i + 1}</span><span class="nm">{esc(t)}</span></li>')
    return (f'<div class="card"><ol class="kc" aria-label="Attack kill chain: {len(active)} of {len(order)} tactics observed">'
            f'{"".join(items)}</ol></div>')


def timeline_view(events: Sequence[Dict], limit: int = 60) -> str:
    """events: dicts with time, title, sig, category, desc."""
    rows = []
    for i, e in enumerate(list(events)[:limit]):
        tone = sev_tone(e.get("sig", ""))
        rows.append(f'<li style="--i:{min(i, 14)};{_tone_style(tone if tone != "neutral" else "info")}">'
                    f'<div class="tm">{esc(e.get("time", ""))}</div>'
                    f'<div class="ti"><b>{esc(e.get("title", ""))}</b>{badge(e.get("category", "event"), "info")}'
                    f'{badge(e.get("sig", "info"), tone) if e.get("sig") else ""}</div>'
                    f'<p>{esc(e.get("desc", ""))}</p></li>')
    return f'<div class="card"><ol class="tl" aria-label="Event timeline">{"".join(rows)}</ol></div>'


_CHEV = '<svg class="tw" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m9 6 6 6-6 6"/></svg>'


def process_tree(nodes: Sequence, flagged: Dict[int, List[str]], only_flagged: bool = False, max_nodes: int = 400) -> str:
    """Collapsible process tree built on <details>/<summary> (keyboard accessible, no JS)."""
    budget = [max_nodes]

    def bad(n) -> bool:
        return n.pid in flagged or getattr(n, "is_hidden", False) or getattr(n, "is_injected", False)

    def has_bad(n) -> bool:
        return bad(n) or any(has_bad(c) for c in n.children)

    def render(n, depth: int) -> str:
        if budget[0] <= 0 or (only_flagged and not has_bad(n)):
            return ""
        budget[0] -= 1
        is_bad = bad(n)
        chips = "".join(badge(r, "critical") for r in flagged.get(n.pid, [])[:3])
        if getattr(n, "is_hidden", False):
            chips += badge("hidden", "high")
        if getattr(n, "is_injected", False):
            chips += badge("injected", "high")
        row = (f'<div class="pt-row{" bad" if is_bad else ""}">{_CHEV if n.children else ""}'
               f'{icon("alert" if is_bad else "cpu", 16)}<span class="nm">{esc(n.name)}</span>'
               f'<code>PID {esc(n.pid)}</code>{chips}</div>')
        detail = ""
        if n.cmdline:
            detail = f'<div class="pt-detail">{esc(n.cmdline[:240])}</div>'
        kids = "".join(render(c, depth + 1) for c in n.children) if depth < 14 else ""
        if not n.children:
            return f'<div class="pt leaf">{row}{detail}</div>'
        return (f'<details class="pt" {"open" if (depth < 2 or has_bad(n)) else ""}><summary>{row}</summary>{detail}'
                f'<div class="pt-kids">{kids}</div></details>')

    body = "".join(render(n, 0) for n in nodes)
    if not body:
        return empty_state("check", "Nothing flagged", "No suspicious process chains in this snapshot.")
    return f'<div class="card pt-wrap" role="tree" aria-label="Process tree">{body}</div>'


__all__ += ["rotating_words", "terminal_feed", "severity_bar", "kill_chain", "timeline_view", "process_tree"]


def meter(value: float, tone: str = "info") -> str:
    v = max(0.0, min(float(value or 0), 100.0))
    return f'<div class="meter" style="{_tone_style(tone)}"><b>{v:.0f}%</b><i style="--w:{v:.0f}%"></i></div>'


def tone_for_verdict(verdict: str) -> str:
    return sev_tone({"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}.get((verdict or "").upper(), "ok"))


__all__ += ["meter", "tone_for_verdict"]
