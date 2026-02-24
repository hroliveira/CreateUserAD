from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE, Tls
import ssl
from config import Config
from logger_config import logger


def get_connection():
    """Cria e retorna uma conexão com o Active Directory."""
    try:
        # Prepara TLS para conexão segura (LDAPS)
        tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

        # Define o servidor (pode ser ldap:// ou ldaps://)
        server = Server(
            Config.AD_SERVER,
            use_ssl=Config.AD_SERVER.startswith("ldaps"),
            tls=tls_config,
            get_info=ALL,
        )

        # Cria a conexão
        conn = Connection(
            server,
            user=Config.AD_USER,
            password=Config.AD_PASSWORD,
            authentication="SIMPLE",
            auto_bind=True,
        )
        return conn
    except Exception as e:
        logger.error(f"Erro ao conectar ao AD: {str(e)}")
        raise Exception(f"Falha na conexão com o servidor AD: {str(e)}")


def create_ad_user(first_name, last_name, username, password, profile_key):
    """
    Cria um usuário no AD, define senha, ativa conta e adiciona a grupos.
    """
    conn = None
    try:
        # Busca detalhes do perfil
        profile = Config.PERFIS.get(profile_key)
        if not profile:
            raise ValueError(
                f"Perfil '{profile_key}' não encontrado nas configurações."
            )

        conn = get_connection()
        user_dn = f"CN={first_name} {last_name},{profile['ou']}"
        display_name = f"{first_name} {last_name}"

        # Extrai o domínio apenas dos componentes DC= da Base DN
        domain_parts = [
            part.split("=")[1]
            for part in Config.AD_BASE_DN.split(",")
            if part.upper().startswith("DC=")
        ]
        domain = ".".join(domain_parts)
        user_principal_name = f"{username}@{domain}"

        # 1. Criar o objeto de usuário
        attrs = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "givenName": first_name,
            "sn": last_name,
            "displayName": display_name,
            "sAMAccountName": username,
            "userPrincipalName": user_principal_name,
            "userAccountControl": 512,  # Normal Account (Inicia desabilitada até ter senha em alguns casos, mas 512 é o alvo)
        }

        logger.info(f"Tentando criar usuário: {user_dn}")
        if not conn.add(user_dn, attributes=attrs):
            error_msg = f"Erro ao adicionar usuário ao AD: {conn.result['description']}"
            logger.error(error_msg)
            return False, error_msg

        # 2. Definir a senha (Requer conexão segura)
        # No AD, a senha deve estar em Unicode (UTF-16-LE) e entre aspas duplas
        unicode_pass = f'"{password}"'.encode("utf-16-le")
        if not conn.extend.microsoft.modify_password(
            user_dn,
            new_password=None,
            old_password=None,
            new_password_unicode=unicode_pass,
        ):
            logger.warning(
                f"Usuário criado mas falha ao definir senha (requer LDAPS): {conn.result['description']}"
            )
            # Nota: Se não for LDAPS, isso geralmente falha.

        # 3. Garantir que a conta está ativa (UAC 512)
        conn.modify(user_dn, {"userAccountControl": [(MODIFY_REPLACE, [512])]})

        # 4. Adicionar aos grupos do perfil
        for group_dn in profile["grupos"]:
            if conn.extend.microsoft.add_members_to_groups(user_dn, group_dn):
                logger.info(f"Usuário adicionado ao grupo: {group_dn}")
            else:
                logger.warning(
                    f"Falha ao adicionar ao grupo {group_dn}: {conn.result['description']}"
                )

        logger.info(f"Usuário {username} criado com sucesso no perfil {profile_key}.")
        return True, "Usuário criado com sucesso!"

    except Exception as e:
        logger.error(f"Erro durante processo de criação: {str(e)}")
        return False, str(e)
    finally:
        if conn:
            conn.unbind()


def authenticate_user(username, password):
    """
    Valida as credenciais do usuário diretamente no AD via BIND.
    Retorna True se autenticado, False caso contrário.
    """
    try:
        # Prepara TLS para conexão segura (LDAPS)
        tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)

        # Define o servidor
        server = Server(
            Config.AD_SERVER,
            use_ssl=Config.AD_SERVER.startswith("ldaps"),
            tls=tls_config,
        )

        # Extrai o domínio apenas dos componentes DC= da Base DN
        domain_parts = [
            part.split("=")[1]
            for part in Config.AD_BASE_DN.split(",")
            if part.upper().startswith("DC=")
        ]
        domain = ".".join(domain_parts)
        user_principal = f"{username}@{domain}"

        # Tenta a conexão com as credenciais fornecidas
        conn = Connection(
            server,
            user=user_principal,
            password=password,
            authentication="SIMPLE",
            auto_bind=True,
        )

        logger.info(f"Autenticação bem-sucedida para o usuário: {username}")
        conn.unbind()
        return True
    except Exception as e:
        logger.warning(f"Falha na autenticação para {username}: {str(e)}")
        return False
