import paypalrestsdk
from typing import Dict
from backend.app.core.config import settings

PAYPAL_CLIENT_ID = settings.PAYPAL_CLIENT_ID
PAYPAL_CLIENT_SECRET = settings.PAYPAL_CLIENT_SECRET

# HUMAN ASSISTANCE NEEDED
# The following function has a confidence level below 0.8 and may need review
def create_payment(amount: float, currency: str, return_url: str, cancel_url: str) -> Dict:
    # SEC-09: payment environment from validated configuration;
    # removes the hardcoded mode literal
    paypalrestsdk.configure({
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


async def process_payment(payment_method: str, amount: float) -> bool:
    if not payment_method:
        return False
    if not isinstance(amount, (int, float)):
        return False
    return amount > 0