from flask import Flask, request, jsonify
import my_pb2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import requests
from key_iv import AES_KEY, AES_IV

import warnings
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

app = Flask(__name__)

DATA_API = "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo"
DECODE_API = "https://team-x-ujjaiwal.vercel.app/decode_jwt"  # NEW DECODE API

HEADERS_TEMPLATE = {
    'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
    'Connection': "Keep-Alive",
    'Accept-Encoding': "gzip",
    'Content-Type': "application/octet-stream",
    'Expect': "100-continue",
    'X-Unity-Version': "2018.4.11f1",
    'X-GA': "v1 1",
    'ReleaseVersion': "OB50",
}

session = requests.Session()

def encrypt_message(key, iv, plaintext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded_message)

def get_user_info_from_api(token):
    try:
        res = requests.get(DECODE_API, params={"jwt_token": token}, timeout=5)  # updated param
        data = res.json()
        decoded = data.get("data", {})  # adjust to match your new API response

        return {
            "uid": decoded.get("account_id", "Unknown"),
            "region": decoded.get("lock_region", "Unknown"),
            "nickname": decoded.get("nickname", "Unknown")
        }
    except Exception as e:
        return {
            "uid": "Error",
            "region": "Error",
            "nickname": f"Error: {str(e)}"
        }

def update_bio_with_token(token, user_bio):
    headers = HEADERS_TEMPLATE.copy()
    headers['Authorization'] = f"Bearer {token}"

    message = my_pb2.Signature()
    message.field2 = 9
    message.field8 = user_bio
    message.field9 = 1

    encrypted_data = encrypt_message(AES_KEY, AES_IV, message.SerializeToString())
    response = session.post(DATA_API, data=encrypted_data, headers=headers, verify=False)

    try:
        response_text = response.content.decode('utf-8')
    except UnicodeDecodeError:
        response_text = response.content.decode('latin1')

    return response.status_code, response_text

@app.route('/updatebio', methods=['GET'])
def api_update_bio():
    token = request.args.get('token')
    bio = request.args.get('bio')

    if not token or not bio:
        return jsonify({
            "status": "error",
            "message": "Missing token or bio!"
        }), 400

    user_info = get_user_info_from_api(token)
    status_code, response_text = update_bio_with_token(token, bio)

    return jsonify({
        "status": "success" if status_code == 200 else "fail",
        "http_status": status_code,
        "message": "✅ Bio updated successfully!" if status_code == 200 else "❌ Bio update failed!",
        "bio_sent": bio,
        "uid": user_info["uid"],
        "region": user_info["region"],
        "nickname": user_info["nickname"],
        "raw_response": response_text
    })

@app.route('/')
def home():
    return "🛡️ API Update Bio\nUsage: /updatebio?token=<TOKEN>&bio=<BIO>"

if __name__ == '__main__':
    app.run(debug=True, port=5000, host="0.0.0.0")
    