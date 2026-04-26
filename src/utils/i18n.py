"""
Internationalization (i18n) utilities for Biubo WAF.
Supports Traditional Chinese (zh-TW), Simplified Chinese (zh-CN), and English (en).
Uses opencc-python for Chinese conversion without external API calls.
"""

import json
import os
from typing import Dict, Optional
from src.config.settings import settings

# Default language
default_lang = "zh-TW"

# Translation dictionaries
_translations: Dict[str, Dict[str, str]] = {
    "zh-TW": {},
    "zh": {},
    "en": {}
}

def _load_translations():
    """Load translation files from the i18n directory."""
    i18n_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'i18n')
    for lang in _translations.keys():
        filepath = os.path.join(i18n_dir, f"{lang}.json")
        if os.path.exists(filepath):
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    _translations[lang] = json.load(f)
            except Exception:
                pass

def get_text(key: str, lang: Optional[str] = None) -> str:
    """
    Get translated text for a given key.
    Falls back to the key itself if translation not found.
    """
    if lang is None:
        lang = getattr(settings, 'UI_LANGUAGE', default_lang)
    
    # Try requested language
    if lang in _translations:
        text = _translations[lang].get(key)
        if text:
            return text
    
    # Fallback to Traditional Chinese
    if default_lang in _translations:
        text = _translations[default_lang].get(key)
        if text:
            return text
    
    # Final fallback: return the key
    return key

def get_current_language() -> str:
    """Get the current UI language setting."""
    return getattr(settings, 'UI_LANGUAGE', default_lang)

def set_language(lang: str):
    """Set the UI language."""
    if lang in _translations:
        settings.UI_LANGUAGE = lang
        settings.save_config()

# Initialize translations on module load
_load_translations()
