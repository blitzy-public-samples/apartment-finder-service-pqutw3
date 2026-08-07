from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from backend.app.core.config import settings
from backend.app.core.logging import get_logger

logger = get_logger(__name__)

SENDGRID_API_KEY = settings.SENDGRID_API_KEY
FROM_EMAIL = settings.FROM_EMAIL

def send_email(to_email: str, subject: str, content: str) -> bool:
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
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