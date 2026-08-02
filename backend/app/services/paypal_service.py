import logging

import paypalrestsdk
from typing import Dict
from backend.app.core.config import settings

# SEC-09/SEC-12: the provider client records the request URL at INFO, and
# that URL carries the client-supplied reference; it records the
# authorization header, the request body and the response body at DEBUG.
# No provider record below this level is emitted (CWE-532).
PROVIDER_LOG_LEVEL = logging.WARNING
_PROVIDER_LOGGER_NAME = "paypalrestsdk"
logging.getLogger(_PROVIDER_LOGGER_NAME).setLevel(PROVIDER_LOG_LEVEL)

PAYPAL_CLIENT_ID = settings.PAYPAL_CLIENT_ID
PAYPAL_CLIENT_SECRET = settings.PAYPAL_CLIENT_SECRET

# HUMAN ASSISTANCE NEEDED
# The following function has a confidence level below 0.8 and may need review
def create_payment(amount: float, currency: str, return_url: str, cancel_url: str) -> Dict:
    paypalrestsdk.configure({
        # SEC-09: environment from validated configuration (CWE-1188)
        "mode": settings.PAYPAL_MODE,
        "client_id": PAYPAL_CLIENT_ID,
        "client_secret": PAYPAL_CLIENT_SECRET
    })

    payment = paypalrestsdk.Payment({
        "intent": "sale",
        "payer": {
            "payment_method": "paypal"
        },
        "redirect_urls": {
            "return_url": return_url,
            "cancel_url": cancel_url
        },
        "transactions": [{
            "amount": {
                "total": str(amount),
                "currency": currency
            },
            "description": "Subscription Payment"
        }]
    })

    if payment.create():
        return payment.to_dict()
    else:
        return {"error": payment.error}

# HUMAN ASSISTANCE NEEDED
# The following function has a confidence level below 0.8 and may need review
def execute_payment(payment_id: str, payer_id: str) -> Dict:
    payment = paypalrestsdk.Payment.find(payment_id)
    
    if payment.execute({"payer_id": payer_id}):
        return payment.to_dict()
    else:
        return {"error": payment.error}


# SEC-09: charge seam for subscriptions.py:24. No trusted plan, price or
# authenticated identity reaches this call. It authorizes nothing and
# refuses every charge (CWE-863)
async def process_payment(payment_method: str, amount: float) -> bool:
    return False
