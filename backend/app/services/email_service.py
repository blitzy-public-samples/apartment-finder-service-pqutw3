from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from backend.app.core.config import settings
from backend.app.core.logging import (
    get_logger,
    log_exception,
    register_required_secret_values,
)

logger = get_logger(__name__)

SENDGRID_API_KEY = settings.SENDGRID_API_KEY
FROM_EMAIL = settings.FROM_EMAIL

#: The one status the Mail Send endpoint reports for a queued message.
#: Every other status, including any other 2xx, is a failure.
ACCEPTED_STATUS = 202

# Replaces the provider credential wherever it appears in a record,
# including in text that names no key such as provider error prose.
register_required_secret_values(SENDGRID_API_KEY)

#: Message recorded when a send does not complete.
EMAIL_FAILURE_MESSAGE = "Failed to send email"

#: Reason recorded with that message.
REASON_SEND_FAILED = "email_send_failed"


def send_email(to_email: str, subject: str, content: str) -> bool:
    """Returns whether the provider queued the message.

    ``True`` is returned only for :data:`ACCEPTED_STATUS`. Every other
    outcome, including another 2xx and any exception the client raises, is
    recorded and reported as ``False``.
    """
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
        if response.status_code != ACCEPTED_STATUS:
            logger.error(
                "Failed to send email",
                extra={
                    "status_code": response.status_code,
                    "expected_status_code": ACCEPTED_STATUS,
                },
            )
            return False
        return True
    except Exception as error:
        log_exception(
            logger,
            EMAIL_FAILURE_MESSAGE,
            error,
            reason=REASON_SEND_FAILED,
        )
        return False
