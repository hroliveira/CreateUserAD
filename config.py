import os
from dotenv import load_dotenv

# Carrega variáveis do arquivo .env
load_dotenv()


class Config:
    """Configurações da aplicação e do Active Directory."""

    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "dev-key-123")

    # Configurações AD
    AD_SERVER = os.getenv("AD_SERVER")
    AD_USER = os.getenv("AD_USER")
    AD_PASSWORD = os.getenv("AD_PASSWORD")
    AD_BASE_DN = os.getenv("AD_BASE_DN")
    _allowed_ou_str = os.getenv("ALLOWED_LOGIN_OU", "")
    ALLOWED_LOGIN_OU = [ou.strip() for ou in _allowed_ou_str.split(";") if ou.strip()]

    # Configurações de Email
    EMAIL_HOST = os.getenv("EMAIL_HOST")
    EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
    EMAIL_USE_TLS = os.getenv("EMAIL_USE_TLS", "True") == "True"
    EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
    EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
    DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL")

    # Extrair domínio curto para uso global
    _parts = [
        p.split("=")[1]
        for p in (AD_BASE_DN or "").split(",")
        if p.upper().startswith("DC=")
    ]
    AD_DOMAIN = ".".join(_parts)

    # Dicionário de Perfis (Cargo -> Grupos e OUs do AD)
    # Adaptado para a estrutura ReisAdv fornecida
    PERFIS = {
        "comercial": {
            "label": "Equipe Comercial",
            "ou": f"OU=Comercial,{AD_BASE_DN}",
            "grupos": [
                f"CN=G_Comercial_Padrao,OU=Grupos,DC=reisadv,DC=com,DC=br",
            ],
        },
        "juridico": {
            "label": "Corpo Jurídico",
            "ou": f"OU=Juridico,{AD_BASE_DN}",
            "grupos": [
                f"CN=G_Juridico_Padrao,OU=Grupos,DC=reisadv,DC=com,DC=br",
            ],
        },
        "ti": {
            "label": "Tecnologia da Informação",
            "ou": f"OU=TI,{AD_BASE_DN}",
            "grupos": [
                f"CN=G_TI_Sistemas,OU=Grupos,DC=reisadv,DC=com,DC=br",
            ],
        },
    }
