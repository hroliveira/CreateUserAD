import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logger():
    """Configura o sistema de log auditável e rotativo."""
    log_dir = "logs"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    log_file = os.path.join(log_dir, "ad_automation.log")

    # Configuração do formatador
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S"
    )

    # Handler para arquivo rotativo (Max 5MB por arquivo, mantém 5 backups)
    file_handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    file_handler.setFormatter(formatter)

    # Handler para console (ajuda no desenvolvimento/debug)
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # Configuração do logger principal
    logger = logging.getLogger("ADAutomation")
    logger.setLevel(logging.INFO)

    # Evita duplicidade de logs se for chamado múltiplas vezes
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)

    return logger


# Instância global do logger
logger = setup_logger()
