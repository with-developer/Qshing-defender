import os, urllib.parse, secrets, base64, requests, ssl, time, datetime
import qrcode as qrtest
from flask import Flask, render_template, request, jsonify
from PIL import Image
from pymongo import MongoClient
from dotenv import load_dotenv
from pysafebrowsing import SafeBrowsing
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from urllib.parse import urlparse

app = Flask(__name__)

# get mongodb environment from .env
load_dotenv(verbose=True)
mongo_server_ip = os.getenv('mongo_server_ip')
mongo_server_port = int(os.getenv('mongo_server_port'))
mongo_account_db = os.getenv('mongo_account_db')
mongo_username = os.getenv('mongo_username')
mongo_password = os.getenv('mongo_password')

virus_total_api_key = "d9f9ae0c053d6d0cadcc6c0432d00810f0cbf7a637e7f53910ec84ab6826815f"

# Qrcode generator init process
Logo_text = './logo.png'
logo = Image.open(Logo_text)
basewidth = 150
wpercent = (basewidth/float(logo.size[0]))
hsize = int((float(logo.size[1])*float(wpercent)))
logo = logo.resize((basewidth, hsize), Image.LANCZOS)

# mongodb connect def
def mongodb_connect():
    username = urllib.parse.quote_plus(mongo_username)
    password = urllib.parse.quote_plus(mongo_password)

    connection_string = f"mongodb://{username}:{password}@{mongo_server_ip}:{mongo_server_port}/?authMechanism=DEFAULT"
    client = MongoClient(connection_string)
    db = client[mongo_account_db]
    return db

def check_phishing_site(url):

    safe_browsing_key = "AIzaSyD9fzcA-q-twD8sWEa6w-BcXbSHltGmtCs"
    s = SafeBrowsing(safe_browsing_key)
    
    # 피싱 여부 확인
    safebrowsing = s.lookup_url(url)
    print(safebrowsing)
    if safebrowsing['malicious'] == True:
        return True
    else:
        return False

def virus_total_api(scan_url,db,random_key):
    print("virus_total_api_start")
    url = f"https://www.virustotal.com/vtapi/v2/url/scan"

    params = {'apikey': virus_total_api_key, 'url': scan_url}

    response_scan = requests.post(url, data=params)

    print(response_scan.text)
    try:
        result_scan = response_scan.json()
    except:
        print("잠시후 다시 시도")
        return "not_ready"
    scan_id = result_scan['scan_id'] 
    print("scan_id:",scan_id)

    url_report = 'https://www.virustotal.com/vtapi/v2/url/report'
    url_report_params = {'apikey': virus_total_api_key, 'resource': scan_id}
    response_report = requests.get(url_report, params=url_report_params)

    report = response_report.json()  # 결과 값을 report에 json형태로 저장
    report_verbose_msg = report.get('verbose_msg')
    report_scans = report.get('scans')  # scans 값 저장
    report_scans_vendors = list(report['scans'].keys())  # Vendor 저장
    report_scans_vendors_cnt = len(report_scans_vendors)  # 길이 저장
    report_scan_data = report.get('scan_data')
    
    for vendor in report_scans_vendors:
        outputs = report_scans[vendor]
        outputs_result = report_scans[vendor].get('result')
        outputs_detected = report_scans[vendor].get('detected')


    # outputs_detected = True, False
    # outputs_result = clean site, unrated site, malware site, malicious site, Phishing site
        if outputs_result != 'clean site':
            if outputs_result != 'unrated site':
                if outputs_detected == True:
                    db.qrcode.update_one({'key': random_key}, {'$set': {f'Detection.{vendor}': "Detected"}})
                print(",[Vendor Name]:", vendor,
                    ',[Vendor Result]:', outputs_result,
                    ',[Vendor Detected]:', outputs_detected)
    return "success"

def get_certificate_info(url):
    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc

        # SSL 컨텍스트 설정 (선택적)
        ssl_context = ssl.create_default_context()

        # 스트림 모드에서 요청 보내기
        response = requests.get(f"https://{host}", timeout=5, verify=False, stream=True)
        cert_data = response.raw.connection.sock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_data, default_backend())

        # 인증서 정보 출력
        print(f"Common Name (CN): {cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value}")
        
        issuer = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
        issuer_name = issuer[0].value if issuer else "Unknown"
        print(f"Issuer: {issuer_name}")
        #print(f"Valid From: {cert.not_valid_before}")
        #print(f"Valid Until: {cert.not_valid_after}")

        # 인증서 검증
        
        trusted_issuers = ["DigiCert Inc", "Cloudflare, Inc.", "Amazon", "Microsoft Corporation", "Google Trust Services LLC", "Sectigo Limited", "GlobalSign nv-sa"]
        
        if issuer_name in trusted_issuers:
            print("정상적인 인증서가 적용된 사이트입니다.")
            return True
        else:
            print("비정상적인 인증서가 적용된 사이트입니다.")
            return False
    except requests.exceptions.RequestException as e:
        print(f"오류: {e}")
        return False

# home route
@app.route('/')
def home():
    return render_template('home.html')

# team route
@app.route('/team')
def team():
    return render_template('team.html')

# qrcode route
@app.route('/qrcode')
def qrcode():

    return render_template('qrcode.html')

# qrcode generator route
@app.route('/API/qr-generator', methods=['POST'])
def qr_generator():
    # get url from post requset
    data = request.json
    url = data.get("url", "")
    only_verify = data.get("options", "")
    print(only_verify)
    
    random_key = secrets.token_hex(16)

    QRcode = qrtest.QRCode(
        error_correction=qrtest.constants.ERROR_CORRECT_H
    )

    QRcode.add_data(f"http://172.30.1.36:5001/certificate?key={random_key}")
    QRcode.make()
    QRcolor = '#00a9ff'
    QRimg = QRcode.make_image(
        fill_color=QRcolor, back_color="white").convert('RGB')
    pos = ((QRimg.size[0] - logo.size[0]) // 2, (QRimg.size[1] - logo.size[1]) // 2)
    QRimg.paste(logo, pos, logo)
    
    image_file = f'qrcode_images/{random_key}.png'
    QRimg.save(image_file)
    
    with open(image_file, 'rb') as img:
        base64_string = base64.b64encode(img.read())
    base64_string = base64_string.decode('utf-8')

    db = mongodb_connect()
    db.qrcode.insert_one({"key" : random_key, "url" : url})
    db.qrcode.update_one({'key' : random_key}, {'$set': {f'logs.{str(datetime.datetime.now())}' : 'created'}})
    
    print('QR code generated!')

    # 피싱 사이트 확인
    answer = check_phishing_site(url)
    print(url)
    if answer == True:
        db.qrcode.update_one({'key': random_key}, {'$set': {'Detection.google_safe_browsing': "Detected"}})
        print("악성사이트입니다.")
    
    vt_api_result = virus_total_api(url,db,random_key)
    if vt_api_result == "not_ready":
        return jsonify({"status":"fail","message":"잠시 후 다시 시도해주세요."})

    certificate_verified = get_certificate_info(url)
    if certificate_verified == True:
        db.qrcode.update_one({'key' : random_key}, {'$set': {'certificate_verified' : True}})
    else:
        db.qrcode.update_one({'key' : random_key}, {'$set': {'certificate_verified' : False}})
    
    if only_verify:
        result_data = db.qrcode.find_one({"key" : random_key})
        try:
            detected_sum = sum(1 for k, v in result_data['Detection'].items() if v == 'Detected')
        except:
            detected_sum = 0
        print(detected_sum)
        certificate_verified = result_data.get('certificate_verified', None)
        print("응답 간다잇!")
        return jsonify({"detected_sum":detected_sum, "certificate_verification":certificate_verified})
    
    result_data = db.qrcode.find_one({"key" : random_key})
    try:
        detected_sum = sum(1 for k, v in result_data['Detection'].items() if v == 'Detected')
    except:
        detected_sum = 0
    if detected_sum != 0:
        return jsonify({"status" : "fail", "message": "악성 URL로 탐지되었습니다."})

    return jsonify({"status" : "success", "base64_image" : base64_string}), 201

@app.route('/certificate', methods=['GET'])
def certificate():
    """TODO
    Get 파라미터의 key 변수 받고
    안전한 페이지입니다 띄운다음에
    3초뒤에 원래 사이트로 리다이렉션
    원래 사이트는 db에서 읽어오면 됨
    """
    key = request.args.get('key', '')
    db = mongodb_connect()
    try:
        certificate_verified = db.qrcode.find_one({"key":key}).get('certificate_verified', None)
    except:
        return render_template('certificate.html',message="존재하지 않는 QR코드입니다.")
    original_url = db.qrcode.find_one({"key":key}).get('url', None)
    print(certificate_verified)
    try:
        detected_sum = sum(1 for k, v in db.qrcode.find_one({"key":key})['Detection'].items() if v == 'Detected')
    except:
        detected_sum = 0
    print(detected_sum)
    if detected_sum != 0:
        return render_template('certificate.html',message="악성 QR코드입니다. 접속할 수 없습니다.")
    elif detected_sum == 0 and certificate_verified == False:
        return render_template('certificate.html',message="\"1등하면 주임님이랑 회식함\" 팀에서 검증한 결과, 악성 QR코드는 아니지만, 미확인된 인증서를 사용하고 있는 사이트입니다.", original_url=original_url)
    elif detected_sum == 0 and certificate_verified == True:
        
        db.qrcode.update_one({'key' : key}, {'$set': {f'logs.{str(datetime.datetime.now())}' : 'access'}})
        return render_template('certificate.html',message="\"1등하면 주임님이랑 회식함\" 팀에서 검증한 안전한 QR코드입니다.", original_url=original_url)
        

@app.route('/qrlog', methods=['GET'])
def qrlog():
    db = mongodb_connect()
    key = request.args.get('detail', None)
    if key == None:
        results = (db.qrcode.find({}, {'url': 1, 'key': 1, '_id': 0}))
        # for result in results:
        #     print(result)
        return render_template('qrlog.html',data=results)
    else:
        results = db.qrcode.find_one({"key":key})
        return render_template('qrlog.html',data2=results)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5001)