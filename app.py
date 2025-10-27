from flask import Flask, request, jsonify
import requests
import re
import json
import time
from urllib.parse import quote

app = Flask(__name__)

# CORS ve header ayarları
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,POST,OPTIONS')
    response.headers.add('X-Powered-By', 'NabiSystem VIP OSINT API')
    return response

class NabiOSINTAPI:
    def __init__(self):
        self.version = "2.0"
        self.author = "NabiSystem VIP"
        
    def log_request(self, module, target):
        print(f"[NABI-API] {module} -> {target}")
    
    # 1. IP GEOLOCATION
    def ip_geolocation(self, ip):
        self.log_request("IP_GEOLOCATION", ip)
        apis = {
            "ipapi": f"https://ipapi.co/{ip}/json/",
            "ip_api": f"http://ip-api.com/json/{ip}",
            "ipwhois": f"https://ipwho.is/{ip}"
        }
        return self.multi_api_request(apis, "IP Geolocation")
    
    # 2. TELEFON ANALIZ
    def phone_analysis(self, phone):
        self.log_request("PHONE_ANALYSIS", phone)
        apis = {
            "numlookup": f"https://api.numlookupapi.com/v1/validate/{phone}?apikey=num_live_wjd4V74gCwHHO4qoxYYEyYO9xBFblGx3twOy0BcU",
            "abstract_phone": f"https://phonevalidation.abstractapi.com/v1/?api_key=9eb8826b744c4b6c8df2b61877071d63&phone={phone}"
        }
        return self.multi_api_request(apis, "Phone Analysis")
    
    # 3. EMAIL OSINT
    def email_osint(self, email):
        self.log_request("EMAIL_OSINT", email)
        apis = {
            "emailrep": f"https://emailrep.io/{email}",
            "hunter": f"https://api.hunter.io/v2/email-verifier?email={email}&api_key=YOUR_KEY"
        }
        return self.multi_api_request(apis, "Email OSINT")
    
    # 4. USERNAME SEARCH
    def username_search(self, username):
        self.log_request("USERNAME_SEARCH", username)
        apis = {
            "whatsmyname": f"https://whatsmyname.app/api/v1/username/{username}",
            "namechk": f"https://namechk.com/availability/{username}"
        }
        return self.multi_api_request(apis, "Username Search")
    
    # 5. YANDEX SEARCH
    def yandex_search(self, query):
        self.log_request("YANDEX_SEARCH", query)
        try:
            encoded_query = quote(query)
            url = f"https://yandex.ru/search/?text={encoded_query}&numdoc=10"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=15)
            
            results = []
            pattern = r'<li class="serp-item">.*?<h2.*?><a.*?href="(.*?)".*?>(.*?)</a>'
            matches = re.findall(pattern, response.text, re.DOTALL)
            
            for match in matches[:5]:
                results.append({
                    "url": match[0],
                    "title": re.sub('<.*?>', '', match[1]),
                    "source": "Yandex"
                })
            
            return {"status": "success", "results": results}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # 6. SOCIAL MEDIA SCANNER
    def social_media_scanner(self, username):
        self.log_request("SOCIAL_MEDIA_SCANNER", username)
        platforms = {
            "instagram": f"https://www.instagram.com/{username}/",
            "twitter": f"https://twitter.com/{username}",
            "github": f"https://github.com/{username}",
            "vk": f"https://vk.com/{username}"
        }
        
        results = {}
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=10)
                results[platform] = "exists" if response.status_code == 200 else "not_found"
            except:
                results[platform] = "error"
        
        return {"status": "success", "results": results}
    
    # 7. VPN DETECTION
    def vpn_detection(self, ip):
        self.log_request("VPN_DETECTION", ip)
        apis = {
            "ip2proxy": f"https://api.ip2proxy.com/?ip={ip}&key=DEMO",
            "vpnapi": f"https://vpnapi.io/api/{ip}?key=YOUR_KEY"
        }
        return self.multi_api_request(apis, "VPN Detection")
    
    # 8. DATA BREACH CHECK
    def breach_check(self, email):
        self.log_request("BREACH_CHECK", email)
        apis = {
            "haveibeenpwned": f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
            "dehashed": f"https://dehashed.com/api/search?query={email}"
        }
        return self.multi_api_request(apis, "Breach Check")
    
    # 9. DOMAIN WHOIS
    def domain_whois(self, domain):
        self.log_request("DOMAIN_WHOIS", domain)
        apis = {
            "whoisxml": f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=JSON",
            "whoisfreaks": f"https://api.whoisfreaks.com/v1.0/whois?whois=live&domainName={domain}"
        }
        return self.multi_api_request(apis, "Domain WHOIS")
    
    # 10. METADATA ANALYSIS
    def metadata_analysis(self, url):
        self.log_request("METADATA_ANALYSIS", url)
        try:
            response = requests.get(url, timeout=15)
            metadata = {
                "content_type": response.headers.get('content-type'),
                "content_length": len(response.content),
                "server": response.headers.get('server'),
                "last_modified": response.headers.get('last-modified')
            }
            return {"status": "success", "metadata": metadata}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # 11. REVERSE IMAGE SEARCH
    def reverse_image_search(self, image_url):
        self.log_request("REVERSE_IMAGE_SEARCH", image_url)
        apis = {
            "google_images": f"https://www.google.com/searchbyimage?image_url={image_url}",
            "yandex_images": f"https://yandex.ru/images/search?url={image_url}"
        }
        return {"status": "success", "apis": apis}
    
    # 12. SCRIPT ANALYSIS
    def script_analysis(self, url):
        self.log_request("SCRIPT_ANALYSIS", url)
        try:
            response = requests.get(url, timeout=10)
            scripts = re.findall(r'<script[^>]*src="([^"]*)"', response.text)
            return {"status": "success", "script_count": len(scripts), "scripts": scripts[:10]}
        except Exception as e:
            return {"status": "error", "message": str(e)}
    
    # 13. BANK BIN CHECK
    def bin_check(self, bin_number):
        self.log_request("BIN_CHECK", bin_number)
        apis = {
            "binlist": f"https://lookup.binlist.net/{bin_number}",
            "bincheck": f"https://api.bincodes.com/bin/?format=json&bin={bin_number}"
        }
        return self.multi_api_request(apis, "BIN Check")
    
    # 14. CRYPTO WALLET ANALYSIS
    def crypto_wallet_analysis(self, wallet_address):
        self.log_request("CRYPTO_WALLET", wallet_address)
        apis = {
            "blockchain_btc": f"https://blockchain.info/rawaddr/{wallet_address}",
            "etherscan": f"https://api.etherscan.io/api?module=account&action=balance&address={wallet_address}"
        }
        return self.multi_api_request(apis, "Crypto Wallet")
    
    # 15. IMEI CHECK
    def imei_check(self, imei):
        self.log_request("IMEI_CHECK", imei)
        apis = {
            "imei_info": f"https://www.imei.info/api/check/{imei}",
            "imeicheck": f"https://api.imeicheck.com/check?imei={imei}"
        }
        return self.multi_api_request(apis, "IMEI Check")
    
    # 16. MAC ADDRESS LOOKUP
    def mac_lookup(self, mac):
        self.log_request("MAC_LOOKUP", mac)
        apis = {
            "macvendors": f"https://api.macvendors.com/{mac}",
            "macaddressio": f"https://api.macaddress.io/v1?apiKey=YOUR_KEY&output=json&search={mac}"
        }
        return self.multi_api_request(apis, "MAC Lookup")
    
    # 17. DOMAIN HISTORY
    def domain_history(self, domain):
        self.log_request("DOMAIN_HISTORY", domain)
        apis = {
            "whoishistory": f"https://api.whoishistory.org/domain/{domain}",
            "archive": f"https://archive.org/wayback/available?url={domain}"
        }
        return self.multi_api_request(apis, "Domain History")
    
    # 18. SSL CERTIFICATE ANALYSIS
    def ssl_analysis(self, domain):
        self.log_request("SSL_ANALYSIS", domain)
        apis = {
            "ssllabs": f"https://api.ssllabs.com/api/v3/analyze?host={domain}",
            "sslcheck": f"https://api.sslcheck.ru/check?host={domain}"
        }
        return self.multi_api_request(apis, "SSL Analysis")
    
    # 19. BROWSER FINGERPRINT
    def browser_fingerprint(self, user_agent):
        self.log_request("BROWSER_FINGERPRINT", user_agent)
        apis = {
            "useragentapi": f"https://api.useragent.dev/parse/{user_agent}",
            "whatismybrowser": f"https://api.whatismybrowser.com/api/v2/user_agent_parse"
        }
        return self.multi_api_request(apis, "Browser Fingerprint")
    
    # 20. DARKNET MONITORING
    def darknet_monitoring(self, query):
        self.log_request("DARKNET_MONITORING", query)
        apis = {
            "ahmia": f"https://ahmia.fi/search/?q={query}",
            "darksearch": f"https://darksearch.io/api/search?query={query}"
        }
        return self.multi_api_request(apis, "Darknet Monitoring")
    
    # 21. TELEGRAM OSINT
    def telegram_osint(self, username):
        self.log_request("TELEGRAM_OSINT", username)
        apis = {
            "telegram": f"https://t.me/{username}",
            "tgstat": f"https://api.tgstat.ru/users/search?q={username}"
        }
        return self.multi_api_request(apis, "Telegram OSINT")
    
    # 22. INSTAGRAM ANALYSIS
    def instagram_analysis(self, username):
        self.log_request("INSTAGRAM_ANALYSIS", username)
        apis = {
            "instagram": f"https://www.instagram.com/{username}/",
            "picuki": f"https://www.picuki.com/profile/{username}"
        }
        return self.multi_api_request(apis, "Instagram Analysis")
    
    # 23. VKONTACTE SCANNER
    def vk_scanner(self, user_id):
        self.log_request("VK_SCANNER", user_id)
        apis = {
            "vk": f"https://vk.com/{user_id}",
            "vk_foaf": f"https://vk.com/foaf.php?id={user_id}"
        }
        return self.multi_api_request(apis, "VK Scanner")
    
    # 24. WHATSAPP DETECTION
    def whatsapp_detection(self, phone):
        self.log_request("WHATSAPP_DETECTION", phone)
        apis = {
            "whatsapp": f"https://wa.me/{phone}",
            "web_whatsapp": f"https://web.whatsapp.com/send?phone={phone}"
        }
        return self.multi_api_request(apis, "WhatsApp Detection")
    
    # 25. BITCOIN TRANSACTIONS
    def bitcoin_transactions(self, address):
        self.log_request("BITCOIN_TRANSACTIONS", address)
        apis = {
            "blockchain": f"https://blockchain.info/rawaddr/{address}",
            "blockchair": f"https://api.blockchair.com/bitcoin/dashboards/address/{address}"
        }
        return self.multi_api_request(apis, "Bitcoin Transactions")
    
    # 26. ETHEREUM ANALYSIS
    def ethereum_analysis(self, address):
        self.log_request("ETHEREUM_ANALYSIS", address)
        apis = {
            "etherscan": f"https://api.etherscan.io/api?module=account&action=balance&address={address}",
            "ethplorer": f"https://api.ethplorer.io/getAddressInfo/{address}?apiKey=freekey"
        }
        return self.multi_api_request(apis, "Ethereum Analysis")
    
    # 27. TAX DATA CHECK (RUSSIAN)
    def tax_data_check(self, inn):
        self.log_request("TAX_DATA_CHECK", inn)
        apis = {
            "nalog_ru": f"https://service.nalog.ru/inn.do?inn={inn}",
            "checko": f"https://api.checko.ru/v2/company?inn={inn}"
        }
        return self.multi_api_request(apis, "Tax Data Check")
    
    # 28. COURT CASES SEARCH (RUSSIAN)
    def court_cases_search(self, name):
        self.log_request("COURT_CASES_SEARCH", name)
        apis = {
            "sudrf": f"https://sudrf.ru/index.php?id=300&act=go_search&searchtype=fs&fio={name}",
            "sudact": f"https://sudact.ru/search/?q={name}"
        }
        return self.multi_api_request(apis, "Court Cases Search")
    
    # 29. PATENT SEARCH
    def patent_search(self, query):
        self.log_request("PATENT_SEARCH", query)
        apis = {
            "fips": f"https://www1.fips.ru/iiss/search.xhtml?q={query}",
            "google_patents": f"https://patents.google.com/?q={query}"
        }
        return self.multi_api_request(apis, "Patent Search")
    
    # 30. TRADEMARK SEARCH
    def trademark_search(self, query):
        self.log_request("TRADEMARK_SEARCH", query)
        apis = {
            "rospatent": f"https://new.fips.ru/registers-web/action?acName=searchTrademark&query={query}",
            "wipo": f"https://www3.wipo.int/branddb/en/?q={query}"
        }
        return self.multi_api_request(apis, "Trademark Search")
    
    # 31. FLIGHT SEARCH
    def flight_search(self, flight_number):
        self.log_request("FLIGHT_SEARCH", flight_number)
        apis = {
            "flightradar24": f"https://www.flightradar24.com/data/flights/{flight_number}",
            "flightstats": f"https://api.flightstats.com/flex/flightstatus/rest/v2/json/flight/status/{flight_number}"
        }
        return self.multi_api_request(apis, "Flight Search")
    
    # 32. HOTEL BOOKING CHECK
    def hotel_booking_check(self, booking_ref):
        self.log_request("HOTEL_BOOKING_CHECK", booking_ref)
        apis = {
            "booking": f"https://www.booking.com/searchresults.ru.html?ss={booking_ref}",
            "tripadvisor": f"https://www.tripadvisor.ru/Search?q={booking_ref}"
        }
        return self.multi_api_request(apis, "Hotel Booking Check")
    
    # 33. RENTAL SEARCH
    def rental_search(self, location):
        self.log_request("RENTAL_SEARCH", location)
        apis = {
            "avito": f"https://www.avito.ru/rossiya?q={location}",
            "cian": f"https://www.cian.ru/cat.php?deal_type=rent&q={location}"
        }
        return self.multi_api_request(apis, "Rental Search")
    
    # 34. CAR PLATE CHECK (RUSSIAN)
    def car_plate_check(self, plate):
        self.log_request("CAR_PLATE_CHECK", plate)
        apis = {
            "avtocod": f"https://avtocod.ru/proverkaavto/{plate}",
            "gibdd": f"https://гибдд.рф/check/auto/?num={plate}"
        }
        return self.multi_api_request(apis, "Car Plate Check")
    
    # 35. DRIVER LICENSE CHECK (RUSSIAN)
    def driver_license_check(self, license_number):
        self.log_request("DRIVER_LICENSE_CHECK", license_number)
        apis = {
            "gibdd_driver": f"https://гибдд.рф/check/driver/?num={license_number}",
            "drom": f"https://www.drom.ru/vin/?w={license_number}"
        }
        return self.multi_api_request(apis, "Driver License Check")
    
    # 36. PASSPORT CHECK (RUSSIAN)
    def passport_check(self, passport_number):
        self.log_request("PASSPORT_CHECK", passport_number)
        apis = {
            "mvd": f"https://мвд.рф/services/check_passport/{passport_number}",
            "fms": f"https://фмс.рф/proverka/{passport_number}"
        }
        return self.multi_api_request(apis, "Passport Check")
    
    # 37. MEDICAL RECORDS SEARCH
    def medical_records_search(self, name):
        self.log_request("MEDICAL_RECORDS_SEARCH", name)
        apis = {
            "emias": f"https://emias.info/patient/{name}",
            "ffoms": f"https://www.ffoms.gov.ru/check/{name}"
        }
        return self.multi_api_request(apis, "Medical Records Search")
    
    # 38. EDUCATION SEARCH
    def education_search(self, name):
        self.log_request("EDUCATION_SEARCH", name)
        apis = {
            "obrnadzor": f"https://obrnadzor.gov.ru/services/check-diplom/{name}",
            "vuzopedia": f"https://vuzopedia.ru/search/{name}"
        }
        return self.multi_api_request(apis, "Education Search")
    
    # 39. WORK HISTORY SEARCH
    def work_history_search(self, name):
        self.log_request("WORK_HISTORY_SEARCH", name)
        apis = {
            "pfr": f"https://pfr.gov.ru/services/work-experience/{name}",
            "gosuslugi": f"https://www.gosuslugi.ru/10050/5/form/{name}"
        }
        return self.multi_api_request(apis, "Work History Search")
    
    # 40. CREDIT HISTORY CHECK
    def credit_history_check(self, name):
        self.log_request("CREDIT_HISTORY_CHECK", name)
        apis = {
            "bki": f"https://www.bki.ru/services/check/{name}",
            "nbki": f"https://www.nbki.ru/services/credit-history/{name}"
        }
        return self.multi_api_request(apis, "Credit History Check")
    
    # 41. REAL ESTATE SEARCH
    def real_estate_search(self, address):
        self.log_request("REAL_ESTATE_SEARCH", address)
        apis = {
            "rosreestr": f"https://rosreestr.gov.ru/wps/portal/p/cc_ib_portal_services/online_request/{address}",
            "yandex_realty": f"https://realty.yandex.ru/moskva_i_moskovskaya_oblast/kupit/kvartira/?text={address}"
        }
        return self.multi_api_request(apis, "Real Estate Search")
    
    # 42. LAND PLOT SEARCH
    def land_plot_search(self, cadastral_number):
        self.log_request("LAND_PLOT_SEARCH", cadastral_number)
        apis = {
            "pkk": f"https://pkk.rosreestr.ru/api/features/1/{cadastral_number}",
            "rosreestr_land": f"https://rosreestr.gov.ru/wps/portal/online_request_land/{cadastral_number}"
        }
        return self.multi_api_request(apis, "Land Plot Search")
    
    # 43. CORPORATE DATA SEARCH
    def corporate_data_search(self, company):
        self.log_request("CORPORATE_DATA_SEARCH", company)
        apis = {
            "egrul": f"https://egrul.nalog.ru/search/{company}",
            "spark": f"https://spark-interfax.ru/search/{company}"
        }
        return self.multi_api_request(apis, "Corporate Data Search")
    
    # 44. MARINE VESSEL SEARCH
    def marine_vessel_search(self, imo):
        self.log_request("MARINE_VESSEL_SEARCH", imo)
        apis = {
            "marinetraffic": f"https://www.marinetraffic.com/ru/ais/details/ships/imo:{imo}",
            "fleetmon": f"https://www.fleetmon.com/vessels/{imo}"
        }
        return self.multi_api_request(apis, "Marine Vessel Search")
    
    # 45. AIRCRAFT SEARCH
    def aircraft_search(self, registration):
        self.log_request("AIRCRAFT_SEARCH", registration)
        apis = {
            "flightaware": f"https://flightaware.com/live/flight/{registration}",
            "flightradar24_aircraft": f"https://www.flightradar24.com/data/aircraft/{registration}"
        }
        return self.multi_api_request(apis, "Aircraft Search")
    
    def multi_api_request(self, apis, service_name):
        results = {"service": service_name, "timestamp": time.time(), "sources": {}}
        
        for name, url in apis.items():
            try:
                response = requests.get(url, timeout=10)
                if response.status_code == 200:
                    try:
                        results["sources"][name] = response.json()
                    except:
                        results["sources"][name] = response.text[:500] + "..." if len(response.text) > 500 else response.text
                else:
                    results["sources"][name] = f"HTTP Error: {response.status_code}"
            except Exception as e:
                results["sources"][name] = f"Request Error: {str(e)}"
        
        return results

# Flask Routes
api = NabiOSINTAPI()

@app.route('/')
def ana_sayfa():
    return jsonify({
        "api": "NabiSystem VIP OSINT API",
        "version": api.version,
        "author": api.author,
        "domain": "system.nabi.22web.org",
        "modules": 45,
        "languages": ["TR", "RU", "EN"],
        "endpoints": {
            "ip_geolocation": "/api/v1/ip?address=IP_ADDRESS",
            "phone_analysis": "/api/v1/phone?number=PHONE_NUMBER", 
            "email_osint": "/api/v1/email?address=EMAIL",
            "username_search": "/api/v1/username?query=USERNAME",
            "yandex_search": "/api/v1/yandex?query=SEARCH_QUERY",
            "social_media": "/api/v1/social?username=USERNAME",
            "vpn_detection": "/api/v1/vpn?ip=IP_ADDRESS",
            "breach_check": "/api/v1/breach?email=EMAIL",
            "domain_whois": "/api/v1/whois?domain=DOMAIN",
            "metadata_analysis": "/api/v1/metadata?url=URL",
            "reverse_image": "/api/v1/reverseimage?url=IMAGE_URL",
            "script_analysis": "/api/v1/script?url=URL",
            "bin_check": "/api/v1/bin?bin=BIN_NUMBER",
            "crypto_wallet": "/api/v1/crypto?address=WALLET_ADDRESS",
            "imei_check": "/api/v1/imei?imei=IMEI_NUMBER",
            "mac_lookup": "/api/v1/mac?address=MAC_ADDRESS",
            "domain_history": "/api/v1/domainhistory?domain=DOMAIN",
            "ssl_analysis": "/api/v1/ssl?domain=DOMAIN",
            "browser_fingerprint": "/api/v1/browser?user_agent=USER_AGENT",
            "darknet_monitoring": "/api/v1/darknet?query=QUERY",
            "telegram_osint": "/api/v1/telegram?username=USERNAME",
            "instagram_analysis": "/api/v1/instagram?username=USERNAME",
            "vk_scanner": "/api/v1/vk?user_id=USER_ID",
            "whatsapp_detection": "/api/v1/whatsapp?phone=PHONE",
            "bitcoin_transactions": "/api/v1/bitcoin?address=WALLET_ADDRESS",
            "ethereum_analysis": "/api/v1/ethereum?address=WALLET_ADDRESS",
            "tax_data": "/api/v1/tax?inn=INN",
            "court_cases": "/api/v1/court?name=NAME",
            "patent_search": "/api/v1/patent?query=QUERY",
            "trademark_search": "/api/v1/trademark?query=QUERY",
            "flight_search": "/api/v1/flight?flight=FLIGHT_NUMBER",
            "hotel_booking": "/api/v1/hotel?booking=BOOKING_REF",
            "rental_search": "/api/v1/rental?location=LOCATION",
            "car_plate": "/api/v1/carplate?plate=PLATE_NUMBER",
            "driver_license": "/api/v1/driverlicense?license=LICENSE_NUMBER",
            "passport_check": "/api/v1/passport?passport=PASSPORT_NUMBER",
            "medical_records": "/api/v1/medical?name=NAME",
            "education_search": "/api/v1/education?name=NAME",
            "work_history": "/api/v1/workhistory?name=NAME",
            "credit_history": "/api/v1/credithistory?name=NAME",
            "real_estate": "/api/v1/realestate?address=ADDRESS",
            "land_plot": "/api/v1/landplot?cadastral=CADASTRAL_NUMBER",
            "corporate_data": "/api/v1/corporate?company=COMPANY",
            "marine_vessel": "/api/v1/marine?imo=IMO_NUMBER",
            "aircraft_search": "/api/v1/aircraft?registration=REGISTRATION"
        },
        "documentation": "https://system.nabi.22web.org/docs"
    })

# TÜM 45 API ENDPOINT
@app.route('/api/v1/ip')
def api_ip():
    address = request.args.get('address')
    if not address:
        return jsonify({"error": "IP address required"}), 400
    return jsonify(api.ip_geolocation(address))

@app.route('/api/v1/phone')
def api_phone():
    number = request.args.get('number')
    if not number:
        return jsonify({"error": "Phone number required"}), 400
    return jsonify(api.phone_analysis(number))

@app.route('/api/v1/email')
def api_email():
    email = request.args.get('address')
    if not email:
        return jsonify({"error": "Email address required"}), 400
    return jsonify(api.email_osint(email))

@app.route('/api/v1/username')
def api_username():
    username = request.args.get('query')
    if not username:
        return jsonify({"error": "Username required"}), 400
    return jsonify(api.username_search(username))

@app.route('/api/v1/yandex')
def api_yandex():
    query = request.args.get('query')
    if not query:
        return jsonify({"error": "Search query required"}), 400
    return jsonify(api.yandex_search(query))

@app.route('/api/v1/social')
def api_social():
    username = request.args.get('username')
    if not username:
        return jsonify({"error": "Username required"}), 400
    return jsonify(api.social_media_scanner(username))

@app.route('/api/v1/vpn')
def api_vpn():
    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "IP address required"}), 400
    return jsonify(api.vpn_detection(ip))

@app.route('/api/v1/breach')
def api_breach():
    email = request.args.get('email')
    if not email:
        return jsonify({"error": "Email required"}), 400
    return jsonify(api.breach_check(email))

@app.route('/api/v1/whois')
def api_whois():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    return jsonify(api.domain_whois(domain))

@app.route('/api/v1/metadata')
def api_metadata():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "URL required"}), 400
    return jsonify(api.metadata_analysis(url))

@app.route('/api/v1/reverseimage')
def api_reverseimage():
    image_url = request.args.get('url')
    if not image_url:
        return jsonify({"error": "Image URL required"}), 400
    return jsonify(api.reverse_image_search(image_url))

@app.route('/api/v1/script')
def api_script():
    url = request.args.get('url')
    if not url:
        return jsonify({"error": "URL required"}), 400
    return jsonify(api.script_analysis(url))

@app.route('/api/v1/bin')
def api_bin():
    bin_number = request.args.get('bin')
    if not bin_number:
        return jsonify({"error": "BIN number required"}), 400
    return jsonify(api.bin_check(bin_number))

@app.route('/api/v1/crypto')
def api_crypto():
    address = request.args.get('address')
    if not address:
        return jsonify({"error": "Wallet address required"}), 400
    return jsonify(api.crypto_wallet_analysis(address))

@app.route('/api/v1/imei')
def api_imei():
    imei = request.args.get('imei')
    if not imei:
        return jsonify({"error": "IMEI number required"}), 400
    return jsonify(api.imei_check(imei))

@app.route('/api/v1/mac')
def api_mac():
    mac = request.args.get('address')
    if not mac:
        return jsonify({"error": "MAC address required"}), 400
    return jsonify(api.mac_lookup(mac))

@app.route('/api/v1/domainhistory')
def api_domainhistory():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    return jsonify(api.domain_history(domain))

@app.route('/api/v1/ssl')
def api_ssl():
    domain = request.args.get('domain')
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    return jsonify(api.ssl_analysis(domain))

@app.route('/api/v1/browser')
def api_browser():
    user_agent = request.args.get('user_agent')
    if not user_agent:
        return jsonify({"error": "User agent required"}), 400
    return jsonify(api.browser_fingerprint(user_agent))

@app.route('/api/v1/darknet')
def api_darknet():
    query = request.args.get('query')
    if not query:
        return jsonify({"error": "Search query required"}), 400
    return jsonify(api.darknet_monitoring(query))

@app.route('/api/v1/telegram')
def api_telegram():
    username = request.args.get('username')
    if not username:
        return jsonify({"error": "Telegram username required"}), 400
    return jsonify(api.telegram_osint(username))

@app.route('/api/v1/instagram')
def api_instagram():
    username = request.args.get('username')
    if not username:
        return jsonify({"error": "Instagram username required"}), 400
    return jsonify(api.instagram_analysis(username))

@app.route('/api/v1/vk')
def api_vk():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "VK user ID required"}), 400
    return jsonify(api.vk_scanner(user_id))

@app.route('/api/v1/whatsapp')
def api_whatsapp():
    phone = request.args.get('phone')
    if not phone:
        return jsonify({"error": "Phone number required"}), 400
    return jsonify(api.whatsapp_detection(phone))

@app.route('/api/v1/bitcoin')
def api_bitcoin():
    address = request.args.get('address')
    if not address:
        return jsonify({"error": "Bitcoin address required"}), 400
    return jsonify(api.bitcoin_transactions(address))

@app.route('/api/v1/ethereum')
def api_ethereum():
    address = request.args.get('address')
    if not address:
        return jsonify({"error": "Ethereum address required"}), 400
    return jsonify(api.ethereum_analysis(address))

@app.route('/api/v1/tax')
def api_tax():
    inn = request.args.get('inn')
    if not inn:
        return jsonify({"error": "INN required"}), 400
    return jsonify(api.tax_data_check(inn))

@app.route('/api/v1/court')
def api_court():
    name = request.args.get('name')
    if not name:
        return jsonify({"error": "Name required"}), 400
    return jsonify(api.court_cases_search(name))

@app.route('/api/v1/patent')
def api_patent():
    query = request.args.get('query')
    if not query:
        return jsonify({"error": "Search query required"}), 400
    return jsonify(api.patent_search(query))

@app.route('/api/v1/trademark')
def api_trademark():
    query = request.args.get('query')
    if not query:
        return jsonify({"error": "Search query required"}), 400
    return jsonify(api.trademark_search(query))

@app.route('/api/v1/flight')
def api_flight():
    flight_number = request.args.get('flight')
    if not flight_number:
        return jsonify({"error": "Flight number required"}), 400
    return jsonify(api.flight_search(flight_number))

@app.route('/api/v1/hotel')
def api_hotel():
    booking_ref = request.args.get('booking')
    if not booking_ref:
        return jsonify({"error": "Booking reference required"}), 400
    return jsonify(api.hotel_booking_check(booking_ref))

@app.route('/api/v1/rental')
def api_rental():
    location = request.args.get('location')
    if not location:
        return jsonify({"error": "Location required"}), 400
    return jsonify(api.rental_search(location))

@app.route('/api/v1/carplate')
def api_carplate():
    plate = request.args.get('plate')
    if not plate:
        return jsonify({"error": "Car plate required"}), 400
    return jsonify(api.car_plate_check(plate))

@app.route('/api/v1/driverlicense')
def api_driverlicense():
    license_number = request.args.get('license')
    if not license_number:
        return jsonify({"error": "Driver license number required"}), 400
    return jsonify(api.driver_license_check(license_number))

@app.route('/api/v1/passport')
def api_passport():
    passport_number = request.args.get('passport')
    if not passport_number:
        return jsonify({"error": "Passport number required"}), 400
    return jsonify(api.passport_check(passport_number))

@app.route('/api/v1/medical')
def api_medical():
    name = request.args.get('name')
    if not name:
        return jsonify({"error": "Name required"}), 400
    return jsonify(api.medical_records_search(name))

@app.route('/api/v1/education')
def api_education():
    name = request.args.get('name')
    if not name:
        return jsonify({"error": "Name required"}), 400
    return jsonify(api.education_search(name))

@app.route('/api/v1/workhistory')
def api_workhistory():
    name = request.args.get('name')
    if not name:
        return jsonify({"error": "Name required"}), 400
    return jsonify(api.work_history_search(name))

@app.route('/api/v1/credithistory')
def api_credithistory():
    name = request.args.get('name')
    if not name:
        return jsonify({"error": "Name required"}), 400
    return jsonify(api.credit_history_check(name))

@app.route('/api/v1/realestate')
def api_realestate():
    address = request.args.get('address')
    if not address:
        return jsonify({"error": "Address required"}), 400
    return jsonify(api.real_estate_search(address))

@app.route('/api/v1/landplot')
def api_landplot():
    cadastral = request.args.get('cadastral')
    if not cadastral:
        return jsonify({"error": "Cadastral number required"}), 400
    return jsonify(api.land_plot_search(cadastral))

@app.route('/api/v1/corporate')
def api_corporate():
    company = request.args.get('company')
    if not company:
        return jsonify({"error": "Company name/INN required"}), 400
    return jsonify(api.corporate_data_search(company))

@app.route('/api/v1/marine')
def api_marine():
    imo = request.args.get('imo')
    if not imo:
        return jsonify({"error": "IMO number required"}), 400
    return jsonify(api.marine_vessel_search(imo))

@app.route('/api/v1/aircraft')
def api_aircraft():
    registration = request.args.get('registration')
    if not registration:
        return jsonify({"error": "Aircraft registration required"}), 400
    return jsonify(api.aircraft_search(registration))

# Health check
@app.route('/health')
def health_check():
    return jsonify({
        "status": "healthy",
        "service": "NabiSystem VIP OSINT API",
        "timestamp": time.time(),
        "version": api.version
    })

# Tüm modüllerin listesi
@app.route('/api/v1/modules')
def api_modules():
    modules = [
        {"id": 1, "name": "IP Geolocation", "endpoint": "/api/v1/ip"},
        {"id": 2, "name": "Phone Analysis", "endpoint": "/api/v1/phone"},
        {"id": 3, "name": "Email OSINT", "endpoint": "/api/v1/email"},
        {"id": 4, "name": "Username Search", "endpoint": "/api/v1/username"},
        {"id": 5, "name": "Yandex Search", "endpoint": "/api/v1/yandex"},
        {"id": 6, "name": "Social Media Scanner", "endpoint": "/api/v1/social"},
        {"id": 7, "name": "VPN Detection", "endpoint": "/api/v1/vpn"},
        {"id": 8, "name": "Data Breach Check", "endpoint": "/api/v1/breach"},
        {"id": 9, "name": "Domain WHOIS", "endpoint": "/api/v1/whois"},
        {"id": 10, "name": "Metadata Analysis", "endpoint": "/api/v1/metadata"},
        {"id": 11, "name": "Reverse Image Search", "endpoint": "/api/v1/reverseimage"},
        {"id": 12, "name": "Script Analysis", "endpoint": "/api/v1/script"},
        {"id": 13, "name": "Bank BIN Check", "endpoint": "/api/v1/bin"},
        {"id": 14, "name": "Crypto Wallet Analysis", "endpoint": "/api/v1/crypto"},
        {"id": 15, "name": "IMEI Check", "endpoint": "/api/v1/imei"},
        {"id": 16, "name": "MAC Address Lookup", "endpoint": "/api/v1/mac"},
        {"id": 17, "name": "Domain History", "endpoint": "/api/v1/domainhistory"},
        {"id": 18, "name": "SSL Certificate Analysis", "endpoint": "/api/v1/ssl"},
        {"id": 19, "name": "Browser Fingerprint", "endpoint": "/api/v1/browser"},
        {"id": 20, "name": "Darknet Monitoring", "endpoint": "/api/v1/darknet"},
        {"id": 21, "name": "Telegram OSINT", "endpoint": "/api/v1/telegram"},
        {"id": 22, "name": "Instagram Analysis", "endpoint": "/api/v1/instagram"},
        {"id": 23, "name": "VKontakte Scanner", "endpoint": "/api/v1/vk"},
        {"id": 24, "name": "WhatsApp Detection", "endpoint": "/api/v1/whatsapp"},
        {"id": 25, "name": "Bitcoin Transactions", "endpoint": "/api/v1/bitcoin"},
        {"id": 26, "name": "Ethereum Analysis", "endpoint": "/api/v1/ethereum"},
        {"id": 27, "name": "Tax Data Check", "endpoint": "/api/v1/tax"},
        {"id": 28, "name": "Court Cases Search", "endpoint": "/api/v1/court"},
        {"id": 29, "name": "Patent Search", "endpoint": "/api/v1/patent"},
        {"id": 30, "name": "Trademark Search", "endpoint": "/api/v1/trademark"},
        {"id": 31, "name": "Flight Search", "endpoint": "/api/v1/flight"},
        {"id": 32, "name": "Hotel Booking Check", "endpoint": "/api/v1/hotel"},
        {"id": 33, "name": "Rental Search", "endpoint": "/api/v1/rental"},
        {"id": 34, "name": "Car Plate Check", "endpoint": "/api/v1/carplate"},
        {"id": 35, "name": "Driver License Check", "endpoint": "/api/v1/driverlicense"},
        {"id": 36, "name": "Passport Check", "endpoint": "/api/v1/passport"},
        {"id": 37, "name": "Medical Records Search", "endpoint": "/api/v1/medical"},
        {"id": 38, "name": "Education Search", "endpoint": "/api/v1/education"},
        {"id": 39, "name": "Work History Search", "endpoint": "/api/v1/workhistory"},
        {"id": 40, "name": "Credit History Check", "endpoint": "/api/v1/credithistory"},
        {"id": 41, "name": "Real Estate Search", "endpoint": "/api/v1/realestate"},
        {"id": 42, "name": "Land Plot Search", "endpoint": "/api/v1/landplot"},
        {"id": 43, "name": "Corporate Data Search", "endpoint": "/api/v1/corporate"},
        {"id": 44, "name": "Marine Vessel Search", "endpoint": "/api/v1/marine"},
        {"id": 45, "name": "Aircraft Search", "endpoint": "/api/v1/aircraft"}
    ]
    return jsonify({"modules": modules, "total": len(modules)})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
