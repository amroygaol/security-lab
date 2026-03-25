import requests
import os
import time
import logging
from datetime import datetime

from prometheus_client import Gauge

from es_store import store_digicert

digicert_cert_total = Gauge(
    "digicert_certificates_total",
    "Total certificates in DigiCert"
)

digicert_cert_active = Gauge(
    "digicert_certificates_active",
    "Active/issued certificates in DigiCert"
)

digicert_cert_expired = Gauge(
    "digicert_certificates_expired",
    "Expired certificates in DigiCert"
)

digicert_cert_revoked = Gauge(
    "digicert_certificates_revoked",
    "Revoked certificates in DigiCert"
)

digicert_cert_expiring_7 = Gauge(
    "digicert_cert_expiring_7_days",
    "Certificates expiring within 7 days"
)

digicert_cert_expiring_14 = Gauge(
    "digicert_cert_expiring_14_days",
    "Certificates expiring within 14 days"
)

digicert_cert_expiring_30 = Gauge(
    "digicert_cert_expiring_30_days",
    "Certificates expiring within 30 days"
)


def collect_digicert():

    api_key = os.getenv("DIGICERT_API_KEY")

    headers = {
        "X-DC-DEVKEY": api_key
    }

    base_url = "https://www.digicert.com/services/v2/order/certificate"
    params = {
        "limit": 1000  # Adjust as needed
    }

    total_certificates = 0
    total_active = 0
    total_expired = 0
    total_revoked = 0
    exp30 = 0
    exp14 = 0
    exp7 = 0
    now = datetime.now()

    page = 1
    while True:
        params['page'] = page
        logging.info(f"DigiCert: Fetching page {page}")
        r = requests.get(base_url, headers=headers, params=params)
        logging.info(f"DigiCert: Page {page} response status {r.status_code}")
        if r.status_code != 200:
            logging.error(f"Error fetching orders: {r.status_code} - {r.text}")
            break

        data = r.json()
        orders = data.get("orders", [])

        for order in orders:
            total_certificates += 1
            status = str(order.get("status", "")).lower()

            if status in ("issued", "active"):
                total_active += 1
                cert = order.get("certificate", {})
                exp_date_str = cert.get("valid_till")
                if exp_date_str:
                    try:
                        exp_date = datetime.strptime(exp_date_str, "%Y-%m-%d")
                        days_left = (exp_date - now).days
                        if 0 <= days_left <= 30:
                            exp30 += 1
                        if 0 <= days_left <= 14:
                            exp14 += 1
                        if 0 <= days_left <= 7:
                            exp7 += 1
                    except (TypeError, ValueError) as e:
                        logging.warning(f"Error parsing expiration date for order {order.get('id', 'unknown')}: {e}")
            elif status == "expired":
                total_expired += 1
            elif status == "revoked":
                total_revoked += 1

        logging.info(f"DigiCert: Page {page} processed {len(orders)} orders")
        # Check if there are more pages
        if len(orders) < params['limit']:
            break
        page += 1

    # Set Prometheus metrics
    digicert_cert_total.set(total_certificates)
    digicert_cert_active.set(total_active)
    digicert_cert_expired.set(total_expired)
    digicert_cert_revoked.set(total_revoked)
    digicert_cert_expiring_30.set(exp30)
    digicert_cert_expiring_14.set(exp14)
    digicert_cert_expiring_7.set(exp7)

    logging.info(
        "Collected: total=%s active=%s expired=%s revoked=%s exp30=%s exp14=%s exp7=%s",
        total_certificates,
        total_active,
        total_expired,
        total_revoked,
        exp30,
        exp14,
        exp7,
    )

    store_digicert(total_certificates, total_active, total_expired,
                   total_revoked, exp30, exp14, exp7)
