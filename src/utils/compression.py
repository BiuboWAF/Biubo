import json
import zlib
import msgpack
import brotli
import logging

logger = logging.getLogger("WAF.Compression")

def compress_json(data) -> bytes:
    """Compress JSON data, prioritizing msgpack + zlib for efficiency."""
    if not isinstance(data, str):
        data = json.dumps(data, separators=(',', ':'))
    # Convert back to dict for msgpack if it was a string
    try:
        obj = json.loads(data) if isinstance(data, str) else data
        packed = msgpack.packb(obj, use_bin_type=True)
        zlibbed = zlib.compress(packed)
        return zlibbed if len(zlibbed) < len(packed) else b"m" + packed
    except Exception as e:
        logger.error(f"compress_json failed: {e}")
        return str(data).encode()

def decompress_json(data: bytes):
    """Decompress data compressed by compress_json."""
    if not data: return {}
    try:
        if data[:1] == b"m":
            return msgpack.unpackb(data[1:], raw=False)
        return msgpack.unpackb(zlib.decompress(data), raw=False)
    except Exception as e:
        logger.error(f"decompress_json failed: {e}")
        return {}

_DECOMPRESSORS = {
    'gzip':    lambda c: zlib.decompress(c, 16 + zlib.MAX_WBITS),
    'deflate': zlib.decompress,
    'br':      brotli.decompress,
}

def decode_content(resp_content: bytes, encoding: str) -> bytes:
    """Decode content based on Content-Encoding header."""
    if not resp_content or not encoding:
        return resp_content
    
    fn = _DECOMPRESSORS.get(encoding.lower())
    if fn:
        try:
            return fn(resp_content)
        except Exception as e:
            logger.error(f"Decompress failed ({encoding}): {e}")
    return resp_content

def encode_content(content: bytes, encoding: str) -> bytes:
    """Compress HTTP response content (optional)."""
    if not content or not encoding:
        return content
        
    encoding = encoding.lower()
    try:
        if 'gzip' in encoding:
            return zlib.compress(content, zlib.Z_BEST_COMPRESSION, 16 + zlib.MAX_WBITS)
        elif 'deflate' in encoding:
            return zlib.compress(content)
        elif 'br' in encoding:
            return brotli.compress(content)
    except Exception:
        pass
    return content
