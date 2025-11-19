import logging
from logging import FileHandler
from pathlib import Path


def setup_logging(log_file: Path | str | None = None, level: int = logging.INFO) -> None:
    root = logging.getLogger()

    if getattr(root, "_ai_monitor_logging_configured", False):
        return

    root.setLevel(level)

    if log_file is None:
        base_dir = Path(__file__).parent
        log_file = base_dir / "ai_monitor.log"
    else:
        log_file = Path(log_file)

    log_file.parent.mkdir(parents=True, exist_ok=True)

    fmt = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    ch = logging.StreamHandler()
    ch.setLevel(level)
    ch.setFormatter(fmt)
    root.addHandler(ch)

    fh = FileHandler(str(log_file), encoding="utf-8")
    fh.setLevel(level)
    fh.setFormatter(fmt)
    root.addHandler(fh)

    root._ai_monitor_logging_configured = True
