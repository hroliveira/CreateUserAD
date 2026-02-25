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


def create_ad_user(first_name, last_name, username, password, profile_key, **kwargs):
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

        user_principal_name = f"{username}@{Config.AD_DOMAIN}"

        # 1. Criar o objeto de usuário
        attrs = {
            "objectClass": ["top", "person", "organizationalPerson", "user"],
            "givenName": first_name,
            "sn": last_name,
            "displayName": display_name,
            "sAMAccountName": username,
            "userPrincipalName": user_principal_name,
            "userAccountControl": 512,
            "title": kwargs.get("job_title", ""),
            "department": kwargs.get("department", ""),
            "physicalDeliveryOfficeName": kwargs.get("office_location", ""),
            "employeeID": kwargs.get("employee_id", ""),
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


def user_exists(username):
    """Verifica se um usuário já existe no AD pelo sAMAccountName."""
    conn = None
    try:
        conn = get_connection()
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        conn.search(Config.AD_BASE_DN, search_filter, attributes=["sAMAccountName"])
        return len(conn.entries) > 0
    except Exception as e:
        logger.error(f"Erro ao verificar existência de usuário {username}: {str(e)}")
        return False
    finally:
        if conn:
            conn.unbind()


def search_users(query):
    """Pesquisa usuários no OU configurado."""
    conn = None
    try:
        conn = get_connection()
        # Filtro para buscar usuários que combinam com o query no nome ou username
        search_filter = f"(&(objectClass=user)(|(sAMAccountName=*{query}*)(displayName=*{query}*)(cn=*{query}*)))"

        # A OU para pesquisa fornecida pelo usuário
        search_base = "OU=Habilitados HML,OU=Restritos,OU=Usuarios,OU=ReisAdv,DC=reisadv,DC=com,DC=br"

        conn.search(
            search_base,
            search_filter,
            search_scope=SUBTREE,
            attributes=[
                "sAMAccountName",
                "displayName",
                "distinguishedName",
                "mail",
                "title",
            ],
        )

        results = []
        for entry in conn.entries:
            results.append(
                {
                    "username": str(entry.sAMAccountName),
                    "display_name": (
                        str(entry.displayName)
                        if hasattr(entry, "displayName")
                        else str(entry.sAMAccountName)
                    ),
                    "dn": str(entry.distinguishedName),
                    "mail": str(entry.mail) if hasattr(entry, "mail") else "",
                    "title": str(entry.title) if hasattr(entry, "title") else "",
                }
            )
        return results
    except Exception as e:
        logger.error(f"Erro ao pesquisar usuários com query '{query}': {str(e)}")
        return []
    finally:
        if conn:
            conn.unbind()


def get_user_details(username):
    """Retorna detalhes completos de um usuário, incluindo grupos e atributos estendidos."""
    conn = None
    try:
        conn = get_connection()
        # Busca o usuário
        search_filter = f"(&(objectClass=user)(sAMAccountName={username}))"
        attributes = [
            "sAMAccountName",
            "displayName",
            "mail",
            "title",
            "department",
            "memberOf",
            "distinguishedName",
            "whenCreated",
            "lastLogon",
            "description",
            "manager",
            "employeeID",
            "physicalDeliveryOfficeName",
            "badPwdCount",
            "userAccountControl",
            "lockoutTime",
            "objectGUID",
        ]
        conn.search(Config.AD_BASE_DN, search_filter, attributes=attributes)

        if len(conn.entries) == 0:
            return None

        entry = conn.entries[0]

        # Processa grupos
        groups = []
        if hasattr(entry, "memberOf"):
            # memberOf can be a string or a list
            member_of = entry.memberOf.value
            if member_of:
                if isinstance(member_of, str):
                    member_of = [member_of]
                for group_dn in member_of:
                    cn = str(group_dn).split(",")[0].replace("CN=", "")
                    groups.append(cn)

        # Tenta pegar o grupo primário (ex: Domain Users)
        # O primaryGroupID é o RID do grupo. O Domain Users é 513 por padrão.
        if "Domain Users" not in groups:
            groups.append("Domain Users")  # Fallback comum em AD

        # Verifica status (Bloqueado/Desativado)
        uac = 512
        if (
            hasattr(entry, "userAccountControl")
            and entry.userAccountControl.value is not None
        ):
            uac = int(entry.userAccountControl.value)
        is_disabled = bool(uac & 2)

        lockout_time = 0
        if hasattr(entry, "lockoutTime") and entry.lockoutTime.value is not None:
            try:
                lockout_time = int(entry.lockoutTime.value)
            except:
                lockout_time = 0
        is_locked = lockout_time > 0

        # Formata Manager (extrai CN)
        manager_cn = "N/A"
        if hasattr(entry, "manager") and entry.manager.value is not None:
            manager_cn = str(entry.manager.value).split(",")[0].replace("CN=", "")

        import uuid

        guid = "N/A"
        if hasattr(entry, "objectGUID") and entry.objectGUID.value is not None:
            try:
                guid_bytes = entry.objectGUID.value
                if isinstance(guid_bytes, bytes) and len(guid_bytes) == 16:
                    guid = str(uuid.UUID(bytes=guid_bytes))
                else:
                    guid = str(guid_bytes)  # Fallback para o valor bruto
            except Exception as uuid_err:
                logger.warning(
                    f"Erro ao converter GUID para {username}: {str(uuid_err)}"
                )
                guid = "N/A"

        return {
            "username": str(entry.sAMAccountName),
            "display_name": (
                str(entry.displayName)
                if hasattr(entry, "displayName") and entry.displayName.value
                else str(entry.sAMAccountName)
            ),
            "mail": (
                str(entry.mail)
                if hasattr(entry, "mail") and entry.mail.value
                else "N/A"
            ),
            "title": (
                str(entry.title)
                if hasattr(entry, "title") and entry.title.value
                else "N/A"
            ),
            "department": (
                str(entry.department)
                if hasattr(entry, "department") and entry.department.value
                else "N/A"
            ),
            "office": (
                str(entry.physicalDeliveryOfficeName)
                if hasattr(entry, "physicalDeliveryOfficeName")
                and entry.physicalDeliveryOfficeName.value
                else "N/A"
            ),
            "description": (
                str(entry.description)
                if hasattr(entry, "description") and entry.description.value
                else "N/A"
            ),
            "employee_id": (
                str(entry.employeeID)
                if hasattr(entry, "employeeID") and entry.employeeID.value
                else "N/A"
            ),
            "manager": manager_cn,
            "bad_pwd_count": (
                int(entry.badPwdCount.value)
                if hasattr(entry, "badPwdCount") and entry.badPwdCount.value is not None
                else 0
            ),
            "is_disabled": is_disabled,
            "is_locked": is_locked,
            "dn": str(entry.distinguishedName),
            "guid": guid,
            "groups": groups,
            "created": (
                str(entry.whenCreated) if hasattr(entry, "whenCreated") else "N/A"
            ),
            "last_logon": (
                str(entry.lastLogon) if hasattr(entry, "lastLogon") else "N/A"
            ),
        }
    except Exception as e:
        logger.error(f"Erro ao obter detalhes de {username}: {str(e)}")
        return None
    finally:
        if conn:
            conn.unbind()


def authenticate_user(username, password):
    """
    Valida as credenciais do usuário diretamente no AD via BIND e verifica a OU.
    Retorna True se autenticado e na OU permitida, False caso contrário.
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

        user_principal = f"{username}@{Config.AD_DOMAIN}"

        # Tenta a conexão com as credenciais fornecidas
        conn = Connection(
            server,
            user=user_principal,
            password=password,
            authentication="SIMPLE",
            auto_bind=True,
        )

        # Se chegou aqui, a senha está correta. Agora vamos verificar a OU.
        if Config.ALLOWED_LOGIN_OU:
            # Busca o DN do usuário autenticado
            conn.search(
                Config.ALLOWED_LOGIN_OU,
                f"(sAMAccountName={username})",
                search_scope=SUBTREE,
            )
            if len(conn.entries) == 0:
                logger.warning(
                    f"Usuário {username} autenticado mas não está na OU permitida."
                )
                conn.unbind()
                return False

        logger.info(f"Autenticação bem-sucedida para o usuário: {username}")
        conn.unbind()
        return True
    except Exception as e:
        logger.warning(f"Falha na autenticação para {username}: {str(e)}")
        return False
