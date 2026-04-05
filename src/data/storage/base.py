import threading
import time
import shutil
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
import os
import msgpack as _msgpack  # type: ignore

class _Codec:
    EXT = ".msgpack"
    @staticmethod
    def dumps(obj: Any) -> bytes:
        return _msgpack.packb(obj, use_bin_type=True)
    @staticmethod
    def loads(data: bytes) -> Any:
        return _msgpack.unpackb(data, raw=False, strict_map_key=False)

class _WriteBehindFlusher(threading.Thread):
    def __init__(self, flush_fn: Callable, interval: float = 1.0):
        super().__init__(daemon=True, name="db-write-behind")
        self._flush_fn = flush_fn
        self._interval = interval
        self._stop_event = threading.Event()

    def run(self) -> None:
        while not self._stop_event.wait(self._interval):
            try:
                self._flush_fn()
            except Exception as exc:
                print(f"[WriteBehind] Flush error: {exc}")

    def stop(self) -> None:
        self._stop_event.set()

class Database:
    """A simple key-value database with write-behind flushing."""
    def __init__(self, path: str, auto_backup: bool = True, max_backup_count: int = 5, flush_interval: float = 1.0):
        self.path = Path(path).resolve()
        if self.path.suffix not in (_Codec.EXT,):
            self.path = self.path.with_suffix(_Codec.EXT)
        self.auto_backup = auto_backup
        self.max_backup_count = max_backup_count
        self._lock = threading.RLock()
        self._data: Dict[str, Any] = {}
        self._dirty: bool = False
        
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write_to_disk()
        else:
            self._read_from_disk()
            
        self._flusher = _WriteBehindFlusher(self._flush_if_dirty, flush_interval)
        self._flusher.start()

    def _write_to_disk(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        with open(tmp, "wb") as f:
            f.write(_Codec.dumps(self._data))
        tmp.replace(self.path)

    def _read_from_disk(self) -> None:
        try:
            with open(self.path, "rb") as f:
                raw = f.read()
            self._data = _Codec.loads(raw) if raw else {}
        except Exception:
            self._data = {}

    def _flush_if_dirty(self) -> None:
        with self._lock:
            if not self._dirty: return
            if self.auto_backup: self._create_backup()
            self._write_to_disk()
            self._dirty = False

    def add(self, key: str, value: Any) -> None:
        with self._lock:
            self._data[key] = value
            self._dirty = True

    def get(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._data.get(key, default)

    def delete(self, key: str) -> bool:
        with self._lock:
            if key not in self._data: return False
            del self._data[key]
            self._dirty = True
            return True

    def flush(self) -> None:
        self._flush_if_dirty()

    def _create_backup(self) -> None:
        try:
            ts = int(time.time())
            backup = self.path.with_suffix(f".backup_{ts}{_Codec.EXT}")
            shutil.copy2(self.path, backup)
            backups = sorted(self.path.parent.glob(f"{self.path.stem}.backup_*{_Codec.EXT}"), key=lambda p: p.stat().st_mtime, reverse=True)
            for old in backups[self.max_backup_count:]: old.unlink()
        except Exception: pass

    def close(self) -> None:
        self._flusher.stop()
        self.flush()

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def __getitem__(self, key: str) -> Any:
        with self._lock:
            if key not in self._data: raise KeyError(key)
            return self._data[key]

    def __setitem__(self, key: str, value: Any) -> None: self.add(key, value)
    def __contains__(self, key: str) -> bool: return key in self._data
    def __len__(self) -> int: return len(self._data)
