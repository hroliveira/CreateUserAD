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

    @property
    def AD_DOMAIN(self):
        """Retorna o domínio formatado a partir da Base DN (ex: reisadv.com.br)."""
        if not self.AD_BASE_DN:
            return ""
        parts = [
            p.split("=")[1]
            for p in self.AD_BASE_DN.split(",")
            if p.upper().startswith("DC=")
        ]
        return ".".join(parts)

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
