"""
Chinese text conversion utility (Simplified <-> Traditional).
Uses opencc-python-reimplemented which works without external API calls.
"""

try:
    import opencc
    _converter_s2t = opencc.OpenCC('s2t')  # Simplified to Traditional
    _converter_t2s = opencc.OpenCC('t2s')  # Traditional to Simplified
    _OPENCC_AVAILABLE = True
except ImportError:
    _OPENCC_AVAILABLE = False
    _converter_s2t = None
    _converter_t2s = None


def s2t(text: str) -> str:
    """
    Convert Simplified Chinese to Traditional Chinese.
    
    Args:
        text: Simplified Chinese text
        
    Returns:
        Traditional Chinese text (or original if conversion unavailable)
    """
    if not _OPENCC_AVAILABLE or not text:
        return text
    try:
        return _converter_s2t.convert(text)
    except Exception:
        return text


def t2s(text: str) -> str:
    """
    Convert Traditional Chinese to Simplified Chinese.
    
    Args:
        text: Traditional Chinese text
        
    Returns:
        Simplified Chinese text (or original if conversion unavailable)
    """
    if not _OPENCC_AVAILABLE or not text:
        return text
    try:
        return _converter_t2s.convert(text)
    except Exception:
        return text


def auto_convert(text: str, target: str = 'zh-TW') -> str:
    """
    Auto-convert Chinese text based on target language preference.
    
    Args:
        text: Input Chinese text (could be Simplified or Traditional)
        target: Target language code ('zh-TW' for Traditional, 'zh' for Simplified)
        
    Returns:
        Converted text in the target format
    """
    if not _OPENCC_AVAILABLE or not text:
        return text
    
    if target == 'zh-TW':
        return s2t(text)
    elif target == 'zh':
        return t2s(text)
    else:
        return text


def is_available() -> bool:
    """Check if Chinese conversion is available."""
    return _OPENCC_AVAILABLE
