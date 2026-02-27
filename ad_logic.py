from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE, Tls
from ldap3.utils.conv import escape_filter_chars
import ssl
import datetime
import uuid
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
        # Higieniza o username para evitar LDAP Injection
        safe_username = escape_filter_chars(username)
        search_filter = f"(&(objectClass=user)(sAMAccountName={safe_username}))"
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
        # Higieniza o query para evitar LDAP Injection
        safe_query = escape_filter_chars(query)
        # Filtro para buscar usuários que combinam com o query no nome ou username
        search_filter = f"(&(objectClass=user)(|(sAMAccountName=*{safe_query}*)(displayName=*{safe_query}*)(cn=*{safe_query}*)))"

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
        # Determina o Root DN para busca global
        root_dn = ",".join([f"DC={p}" for p in Config.AD_DOMAIN.split(".")])

        # Higieniza o username para evitar LDAP Injection
        safe_username = escape_filter_chars(username)
        # Busca o usuário em todo o domínio
        search_filter = f"(&(objectClass=user)(sAMAccountName={safe_username}))"
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
            "lastLogonTimestamp",
            "pwdLastSet",
            "accountExpires",
            "userWorkstations",
            "scriptPath",
            "profilePath",
            "homeDirectory",
            "homeDrive",
            "countryCode",
            "logonHours",
            "comment",
            "msDS-UserPasswordExpiryTimeComputed",
        ]

        # Scope SUBTREE é fundamental para encontrar em qualquer OU
        conn.search(root_dn, search_filter, search_scope=SUBTREE, attributes=attributes)

        if len(conn.entries) == 0:
            return None

        entry = conn.entries[0]

        # Processa grupos (Busca robusta combinando métodos)
        groups_set = set()
        user_dn = entry.distinguishedName.value

        # Determina o Root DN para busca global de grupos
        root_dn = ",".join([f"DC={p}" for p in Config.AD_DOMAIN.split(".")])

        # Método 1: Atributo memberOf do usuário
        if hasattr(entry, "memberOf") and entry.memberOf.value:
            mo = entry.memberOf.value
            if isinstance(mo, str):
                mo = [mo]
            for g_dn in mo:
                cn = str(g_dn).split(",")[0].replace("CN=", "")
                groups_set.add(cn)

        # Método 2: Pesquisa reversa nos grupos (Atributo member) - Busca em todo o domínio
        try:
            group_filter = f"(&(objectClass=group)(member={user_dn}))"
            conn.search(root_dn, group_filter, attributes=["cn"])
            for g_entry in conn.entries:
                if hasattr(g_entry, "cn") and g_entry.cn.value:
                    groups_set.add(str(g_entry.cn.value))
        except Exception as e:
            logger.warning(f"Erro na busca reversa de grupos para {username}: {str(e)}")

        groups = sorted(list(groups_set))

        # Tenta incluir o grupo primário se não estiver na lista (Localizado)
        primary_term = "Usuários do domínio"
        if not any(
            g.lower() in [s.lower() for s in groups]
            for g in ["Domain Users", primary_term]
        ):
            groups.append(primary_term)
            groups.sort()

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

        def ad_timestamp_to_datetime(val):
            """Converte timestamp do AD (ou objeto datetime) para string formatada."""
            # Valores que indicam que a data nunca foi definida ou é o início da época AD
            if (
                not val
                or val == 0
                or str(val) == "0"
                or str(val).startswith("1601-01-01")
            ):
                return "Nunca"

            # Se já for um objeto datetime
            if isinstance(val, datetime.datetime):
                if val.year <= 1601:
                    return "Nunca"
                return val.strftime("%d/%m/%Y %H:%M:%S")

            try:
                # Se for uma representação de data em string formatada do ldap3
                val_str = str(val)
                if "-" in val_str and ":" in val_str:
                    if val_str.startswith("1601-01-01"):
                        return "Nunca"
                    return val_str

                # Tenta converter para int (AD timestamp: 100ns desde 1601)
                val_int = int(val)
                if val_int <= 0:
                    return "Nunca"

                # AD timestamp is 100-nanosecond intervals since Jan 1, 1601
                seconds = val_int / 10000000
                dt = datetime.datetime(1601, 1, 1) + datetime.timedelta(seconds=seconds)

                if dt.year <= 1601:
                    return "Nunca"
                return dt.strftime("%d/%m/%Y %H:%M:%S")
            except Exception as e:
                # Se falhar a conversão numérica, retornamos Nunca apenas se for zero/falso
                return "Nunca" if not val or str(val) == "0" else "N/A"

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

        # Formata Last Logon (AD tem lastLogon e lastLogonTimestamp)
        ll_raw = entry.lastLogon.value if hasattr(entry, "lastLogon") else 0
        lts_raw = (
            entry.lastLogonTimestamp.value
            if hasattr(entry, "lastLogonTimestamp")
            else 0
        )

        # Pega o mais recente de forma segura
        def get_val_for_max(v):
            if isinstance(v, datetime.datetime):
                return v
            try:
                val_int = int(v or 0)
                if val_int <= 0:
                    return datetime.datetime(1601, 1, 1)
                return datetime.datetime(1601, 1, 1) + datetime.timedelta(
                    seconds=val_int / 10000000
                )
            except:
                return datetime.datetime(1601, 1, 1)

        last_logon_raw = max(get_val_for_max(ll_raw), get_val_for_max(lts_raw))

        last_logon_fmt = ad_timestamp_to_datetime(last_logon_raw)

        # Datas de senha e conta
        pwd_last_set_raw = (
            entry.pwdLastSet.value
            if hasattr(entry, "pwdLastSet") and entry.pwdLastSet.value is not None
            else 0
        )
        pwd_last_set_fmt = ad_timestamp_to_datetime(pwd_last_set_raw)

        # Password Expiry (msDS-UserPasswordExpiryTimeComputed)
        pwd_expires_raw = getattr(entry, "msDS-UserPasswordExpiryTimeComputed", 0)
        if hasattr(pwd_expires_raw, "value"):
            pwd_expires_raw = pwd_expires_raw.value

        if not pwd_expires_raw or int(str(pwd_expires_raw)) >= 9223372036854775807:
            pwd_expires_fmt = "Nunca"
        else:
            pwd_expires_fmt = ad_timestamp_to_datetime(pwd_expires_raw)

        # Account Expires
        acc_expires_raw = (
            entry.accountExpires.value if hasattr(entry, "accountExpires") else 0
        )
        if (
            not acc_expires_raw
            or int(str(acc_expires_raw)) >= 9223372036854775807
            or int(str(acc_expires_raw)) == 0
        ):
            acc_expires_fmt = "Nunca"
        else:
            acc_expires_fmt = ad_timestamp_to_datetime(acc_expires_raw)

        # UAC Flags adicionais
        password_required = not bool(uac & 32)  # UF_PASSWD_NOTREQD = 32
        can_change_password = not bool(uac & 64)  # UF_PASSWD_CANT_CHANGE = 64

        # Metadados de Perfil e Sistema
        workstations = (
            str(entry.userWorkstations.value)
            if hasattr(entry, "userWorkstations") and entry.userWorkstations.value
            else "Todos"
        )
        script_path = (
            str(entry.scriptPath.value)
            if hasattr(entry, "scriptPath") and entry.scriptPath.value
            else "N/A"
        )
        profile_path = (
            str(entry.profilePath.value)
            if hasattr(entry, "profilePath") and entry.profilePath.value
            else "N/A"
        )
        home_directory = (
            str(entry.homeDirectory.value)
            if hasattr(entry, "homeDirectory") and entry.homeDirectory.value
            else "N/A"
        )
        home_drive = (
            str(entry.homeDrive.value)
            if hasattr(entry, "homeDrive") and entry.homeDrive.value
            else ""
        )
        if home_drive and home_directory != "N/A":
            home_path = f"{home_drive} -> {home_directory}"
        else:
            home_path = home_directory

        country_code = (
            str(entry.countryCode.value)
            if hasattr(entry, "countryCode") and entry.countryCode.value
            else "000 (Padrão)"
        )
        comment = (
            str(entry.comment.value)
            if hasattr(entry, "comment") and entry.comment.value
            else "N/A"
        )

        # O whenCreated já vem como datetime do ldap3 geralmente, mas vamos garantir
        created_raw = (
            entry.whenCreated.value if hasattr(entry, "whenCreated") else "N/A"
        )
        created_fmt = str(created_raw).split(".")[0] if created_raw != "N/A" else "N/A"

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
            "created": created_fmt,
            "last_logon": last_logon_fmt,
            # Novos campos
            "pwd_last_set": pwd_last_set_fmt,
            "pwd_expires": pwd_expires_fmt,
            "acc_expires": acc_expires_fmt,
            "password_required": password_required,
            "can_change_password": can_change_password,
            "workstations": workstations,
            "script_path": script_path,
            "profile_path": profile_path,
            "home_path": home_path,
            "country_code": country_code,
            "comment": comment,
            "logon_hours": "Todos",  # Simplificado
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

        # Higieniza o username para evitar LDAP Injection
        safe_username = escape_filter_chars(username).strip()
        user_principal = f"{safe_username}@{Config.AD_DOMAIN}"

        # Tenta a conexão com as credenciais fornecidas
        conn = Connection(
            server,
            user=user_principal,
            password=password,
            authentication="SIMPLE",
            auto_bind=True,
        )

        # Se chegou aqui, a senha está correta. Agora vamos verificar as OUs.
        if Config.ALLOWED_LOGIN_OU:
            user_found_in_ou = False
            for ou in Config.ALLOWED_LOGIN_OU:
                # Busca o DN do usuário autenticado dentro de cada OU permitida
                conn.search(
                    ou,
                    f"(sAMAccountName={safe_username})",
                    search_scope=SUBTREE,
                )
                if len(conn.entries) > 0:
                    user_found_in_ou = True
                    break

            if not user_found_in_ou:
                logger.warning(
                    f"Usuário {username} autenticado mas não está em nenhuma das OUs permitidas."
                )
                conn.unbind()
                return False

        logger.info(f"Autenticação bem-sucedida para o usuário: {username}")
        conn.unbind()
        return True
    except Exception as e:
        logger.warning(f"Falha na autenticação para {username}: {str(e)}")
        return False
