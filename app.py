"""
PhishingAI — Interface de démonstration Streamlit
"""

import os
import tempfile
from pathlib import Path

import streamlit as st
from deep_translator import GoogleTranslator

from analyzer import analyze_eml, parse_eml, _msg_to_eml

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

MODELS = ["llama3", "qwen2.5", "mistral-nemo"]

LANG_LABELS = {"fr": "Français", "en": "English", "de": "Deutsch"}

VERDICT_CONFIG = {
    "malveillant": {"color": "#e63946", "icon": "🔴", "label": {"fr": "Malveillant", "en": "Malicious", "de": "Bösartig"}},
    "suspect":     {"color": "#f4a261", "icon": "🟠", "label": {"fr": "Suspect",     "en": "Suspicious", "de": "Verdächtig"}},
    "légitime":    {"color": "#2a9d8f", "icon": "🟢", "label": {"fr": "Légitime",    "en": "Legitimate", "de": "Legitim"}},
}

UI_STRINGS = {
    "fr": {
        "title": "PhishingAI — Analyse d'emails",
        "subtitle": "Déposez un fichier .eml ou .msg pour l'analyser",
        "upload_label": "Fichier email (.eml ou .msg)",
        "model_label": "Modèle d'analyse",
        "lang_label": "Langue de l'interface",
        "analyze_btn": "Analyser",
        "analyzing": "Analyse en cours...",
        "score": "Score de risque",
        "verdict": "Verdict",
        "reasons": "Raisons",
        "tags": "Tags",
        "recommendation": "Recommandation",
        "no_file": "Déposez un fichier pour commencer.",
        "step_parsing": "Lecture et parsing du mail...",
        "step_parsing_done": "Mail parsé",
        "step_urls": "Vérification des URLs",
        "step_urls_unit": "domaines vérifiés",
        "step_urls_done": "{n} domaines vérifiés",
        "step_llm": "Analyse par le modèle...",
        "step_llm_done": "Analyse terminée",
        "headers": "En-têtes extraits",
        "from": "Expéditeur",
        "subject": "Sujet",
        "spf": "SPF",
        "dkim": "DKIM",
    },
    "en": {
        "title": "PhishingAI — Email Analysis",
        "subtitle": "Drop a .eml or .msg file to analyze it",
        "upload_label": "Email file (.eml or .msg)",
        "model_label": "Analysis model",
        "lang_label": "Interface language",
        "analyze_btn": "Analyze",
        "analyzing": "Analyzing...",
        "score": "Risk score",
        "verdict": "Verdict",
        "reasons": "Reasons",
        "tags": "Tags",
        "recommendation": "Recommendation",
        "no_file": "Drop a file to get started.",
        "step_parsing": "Reading and parsing email...",
        "step_parsing_done": "Email parsed",
        "step_urls": "Checking URLs",
        "step_urls_unit": "domains checked",
        "step_urls_done": "{n} domains checked",
        "step_llm": "Running model analysis...",
        "step_llm_done": "Analysis complete",
        "headers": "Extracted headers",
        "from": "Sender",
        "subject": "Subject",
        "spf": "SPF",
        "dkim": "DKIM",
    },
    "de": {
        "title": "PhishingAI — E-Mail-Analyse",
        "subtitle": "Legen Sie eine .eml- oder .msg-Datei ab, um sie zu analysieren",
        "upload_label": "E-Mail-Datei (.eml oder .msg)",
        "model_label": "Analysemodell",
        "lang_label": "Sprache",
        "analyze_btn": "Analysieren",
        "analyzing": "Analyse läuft...",
        "score": "Risikobewertung",
        "verdict": "Urteil",
        "reasons": "Gründe",
        "tags": "Tags",
        "recommendation": "Empfehlung",
        "no_file": "Legen Sie eine Datei ab, um zu beginnen.",
        "step_parsing": "E-Mail wird gelesen und geparst...",
        "step_parsing_done": "E-Mail geparst",
        "step_urls": "URLs werden überprüft",
        "step_urls_unit": "Domains geprüft",
        "step_urls_done": "{n} Domains geprüft",
        "step_llm": "Modellanalyse läuft...",
        "step_llm_done": "Analyse abgeschlossen",
        "headers": "Extrahierte Header",
        "from": "Absender",
        "subject": "Betreff",
        "spf": "SPF",
        "dkim": "DKIM",
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def translate_text(text: str, target_lang: str) -> str:
    """Traduit un texte vers target_lang via GoogleTranslator (deep-translator)."""
    if target_lang == "fr" or not text:
        return text
    try:
        return GoogleTranslator(source="auto", target=target_lang).translate(text)
    except Exception:
        return text  # fallback silencieux


def translate_result(result: dict, lang: str) -> dict:
    """Traduit les champs textuels du verdict."""
    if lang == "fr":
        return result
    translated = result.copy()
    translated["raisons"] = [translate_text(r, lang) for r in result.get("raisons", [])]
    if result.get("recommandation"):
        translated["recommandation"] = translate_text(result["recommandation"], lang)
    return translated


def score_color(score: int) -> str:
    if score >= 70:
        return "#e63946"
    if score >= 45:
        return "#f4a261"
    return "#2a9d8f"


def render_gauge(score: int):
    """Affiche une jauge de score avec st.progress + metric."""
    color = score_color(score)
    st.markdown(
        f"""
        <div style="text-align:center; margin-bottom: 0.5rem;">
            <span style="font-size: 3rem; font-weight: 800; color: {color};">{score}</span>
            <span style="font-size: 1.2rem; color: #888;">/100</span>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.progress(score / 100)


def render_verdict_badge(verdict: str, lang: str):
    cfg = VERDICT_CONFIG.get(verdict, VERDICT_CONFIG["suspect"])
    label = cfg["label"].get(lang, verdict)
    st.markdown(
        f"""
        <div style="
            display: inline-block;
            background-color: {cfg['color']};
            color: white;
            padding: 0.4rem 1.2rem;
            border-radius: 999px;
            font-size: 1.1rem;
            font-weight: 700;
            margin-bottom: 1rem;
        ">{cfg['icon']} {label}</div>
        """,
        unsafe_allow_html=True,
    )


def render_tags(tags: list[str]):
    html = " ".join(
        f'<span style="background:#334155;color:#e2e8f0;padding:2px 10px;'
        f'border-radius:999px;font-size:0.8rem;margin:2px;display:inline-block;">{t}</span>'
        for t in tags
    )
    st.markdown(html, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

st.set_page_config(page_title="PhishingAI", page_icon="🎣", layout="wide")

# Sidebar — langue + modèle
with st.sidebar:
    lang = st.selectbox("🌐", list(LANG_LABELS.keys()), format_func=lambda k: LANG_LABELS[k], key="lang")
    s = UI_STRINGS[lang]

    st.divider()
    model = st.selectbox(s["model_label"], MODELS, key="model")

# Main
st.title(s["title"])
st.caption(s["subtitle"])

uploaded = st.file_uploader(s["upload_label"], type=["eml", "msg"], label_visibility="collapsed")

if not uploaded:
    st.info(s["no_file"])
    st.stop()

# Bouton analyse
if st.button(s["analyze_btn"], type="primary", use_container_width=True):
    suffix = Path(uploaded.name).suffix.lower()

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(uploaded.read())
        tmp_path = tmp.name

    try:
        # --- Étape 1 : parsing ---
        step1 = st.status(s["step_parsing"], expanded=False)
        with step1:
            if suffix == ".msg":
                eml_content = _msg_to_eml(tmp_path)
            else:
                with open(tmp_path, "r", encoding="utf-8", errors="replace") as f:
                    eml_content = f.read()
            parsed_preview = parse_eml(eml_content)
            n_urls = len(parsed_preview["urls"])
        step1.update(label=s["step_parsing_done"], state="complete")

        # --- Étape 2 : enrichissement URLs ---
        step2_label = st.empty()
        step2_bar   = st.empty()
        step2_label.markdown(f"**{s['step_urls']}**")
        bar2 = step2_bar.progress(0.0)

        def url_progress(current, total):
            pct = current / total if total else 1.0
            bar2.progress(pct, text=f"{current}/{total} {s['step_urls_unit']}")
            if current == total:
                step2_label.markdown(f"**{s['step_urls_done'].format(n=total)}**")

        # --- Étape 3 : inférence LLM ---
        step3_label = st.empty()
        step3_bar   = st.empty()
        step3_label.markdown(f"**{s['step_llm']}**")
        bar3 = step3_bar.progress(0.0)

        ESTIMATED_TOKENS = 300
        token_count = [0]

        def on_token(token: str):
            token_count[0] += 1
            pct = min(token_count[0] / ESTIMATED_TOKENS, 0.99)
            bar3.progress(pct)

        result = analyze_eml(
            eml_content, model=model,
            on_url_progress=url_progress,
            on_token=on_token,
        )

        bar2.progress(1.0)
        bar3.progress(1.0, text=s["step_llm_done"])
        step3_label.markdown(f"**{s['step_llm_done']}**")

        result = translate_result(result, lang)
        st.session_state["result"] = result
        st.session_state["eml_content"] = eml_content
    finally:
        os.unlink(tmp_path)

# Affichage du résultat
if "result" not in st.session_state:
    st.stop()

result = st.session_state["result"]
verdict = result.get("verdict", "suspect")
score   = result.get("score", 50)

col_score, col_verdict, col_meta = st.columns([1, 1, 2])

with col_score:
    st.subheader(s["score"])
    render_gauge(score)

with col_verdict:
    st.subheader(s["verdict"])
    render_verdict_badge(verdict, lang)
    tags = result.get("tags", [])
    if tags:
        render_tags(tags)

with col_meta:
    # En-têtes extraits
    parsed = parse_eml(st.session_state["eml_content"])
    h = parsed["headers"]
    st.subheader(s["headers"])
    st.markdown(f"**{s['from']}** : `{h['from']}`")
    st.markdown(f"**{s['subject']}** : {h['subject']}")
    st.markdown(f"**{s['spf']}** : `{h['spf']}`  |  **{s['dkim']}** : `{'présent' if h['dkim'] != 'absent' else 'absent'}`")

st.divider()

col_reasons, col_reco = st.columns([2, 1])

with col_reasons:
    st.subheader(s["reasons"])
    for r in result.get("raisons", []):
        st.markdown(f"- {r}")

with col_reco:
    reco = result.get("recommandation", "")
    if reco:
        st.subheader(s["recommendation"])
        cfg = VERDICT_CONFIG.get(verdict, VERDICT_CONFIG["suspect"])
        st.info(reco)
