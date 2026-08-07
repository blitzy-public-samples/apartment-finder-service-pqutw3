from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from backend.app.core.config import settings
from backend.app.core.logging import get_logger, register_secret_values

logger = get_logger(__name__)

SENDGRID_API_KEY = settings.SENDGRID_API_KEY
FROM_EMAIL = settings.FROM_EMAIL

# Replaces the provider credential wherever it appears in a record, so it
# is removed from text that names no key -- provider error prose included.
register_secret_values(SENDGRID_API_KEY)

def send_email(to_email: str, subject: str, content: str) -> bool:
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        # Bounds the underlying request; propagated to every chained
        # sub-client the send call builds.
        sg.client.timeout = settings.HTTP_TIMEOUT_SECONDS
        message = Mail(
            from_email=FROM_EMAIL,
            to_emails=to_email,
            subject=subject,
            html_content=content
        )
        response = sg.send(message)
        return response.status_code in [200, 201, 202]
    except Exception as e:
        logger.error("Failed to send email", exc_info=e)
        return False