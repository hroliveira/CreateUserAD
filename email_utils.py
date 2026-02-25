import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import Config
from logger_config import logger


def send_provisioning_email(user_data):
    """
    Envia um e-mail de notificação após a criação de um novo usuário.
    """
    if not Config.EMAIL_HOST_USER:
        logger.warning(
            "Configurações de e-mail não encontradas no .env. Ignorando envio."
        )
        return False

    try:
        msg = MIMEMultipart()
        msg["From"] = Config.DEFAULT_FROM_EMAIL
        msg["To"] = (
            Config.EMAIL_HOST_USER
        )  # Enviando para o admin ou e-mail configurado
        msg["Subject"] = f"Novo Usuário Provisionado: {user_data['username']}"

        body = f"""
        <html>
        <body style="font-family: sans-serif; color: #333;">
            <h2 style="color: #0ddff2;">Notificação de Provisionamento</h2>
            <p>Um novo usuário foi criado com sucesso no Active Directory.</p>
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="background-color: #f8f9fa;">
                    <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Nome Completo:</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{user_data['first_name']} {user_data['last_name']}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Login (UPN):</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{user_data['username']}@{Config.AD_DOMAIN}</td>
                </tr>
                <tr style="background-color: #f8f9fa;">
                    <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Cargo:</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{user_data['job_title']}</td>
                </tr>
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold;">Departamento:</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{user_data['department']}</td>
                </tr>
            </table>
            <br>
            <p style="font-size: 0.8em; color: #777;">Este é um e-mail automático enviado pelo Portal Modern Ops AD Manager.</p>
        </body>
        </html>
        """

        msg.attach(MIMEText(body, "html"))

        # Conecta ao servidor SMTP
        server = smtplib.SMTP(Config.EMAIL_HOST, Config.EMAIL_PORT)
        if Config.EMAIL_USE_TLS:
            server.starttls()

        server.login(Config.EMAIL_HOST_USER, Config.EMAIL_HOST_PASSWORD)
        server.send_message(msg)
        server.quit()

        logger.info(f"E-mail de notificação enviado para {user_data['username']}.")
        return True
    except Exception as e:
        logger.error(f"Erro ao enviar e-mail: {str(e)}")
        return False
