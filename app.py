import hashlib
import re
import requests
from flask import Flask, render_template, request, jsonify
from zxcvbn import zxcvbn

app = Flask(__name__)

# Load common names dataset
with open('common_names.txt') as f:
    COMMON_NAMES = {name.strip().lower() for name in f}


def check_hibp(password):
    """
    Check if password has been exposed in a data breach using HIBP k-Anonymity API.
    Returns:
        - int: number of times the password was found in breaches
        - -1: if API fails
    """
    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]

    try:
        headers = {
            'User-Agent': 'PasswordSecurityChecker/1.0 (nichokechukwu@gmail.com)'
        }
        response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', headers=headers, timeout=2)
        response.raise_for_status()

        for line in response.text.splitlines():
            hash_suffix, count = line.strip().split(':')
            if hash_suffix == suffix:
                return int(count)
        return 0
    except requests.RequestException as e:
        print(f"[HIBP API Error] {e}")
        return -1


def detect_contextual_weaknesses(password):
    """Detect contextual weaknesses using NLP techniques"""
    weaknesses = []
    password_lower = password.lower()

    # Check for common names
    for name in COMMON_NAMES:
        if len(name) > 2 and name in password_lower:
            weaknesses.append(f"Contains common name: '{name}'")
            break

    # Check for date patterns (YYYY, YY, DD/MM, MM/DD)
    date_patterns = [
        r'\b(19|20)\d{2}\b',  # Years 1900-2099
        r'\b\d{1,2}[/-]\d{1,2}\b',  # DD/MM or MM/DD
        r'\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b'  # YYYY-MM-DD
    ]
    for pattern in date_patterns:
        if re.search(pattern, password):
            weaknesses.append("Contains date pattern")
            break

    # Check keyboard patterns
    keyboard_patterns = [
        'qwerty', 'asdfgh', 'zxcvbn', '123456',
        'password', 'letmein', 'welcome', 'admin'
    ]
    for pattern in keyboard_patterns:
        if pattern in password_lower:
            weaknesses.append(f"Contains common pattern: '{pattern}'")
            break

    return weaknesses


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/check', methods=['POST'])
def check_password():
    password = request.form.get('password', '')

    if not password:
        return jsonify({'error': 'No password provided'})

    # Step 1: Breach check
    breach_count = check_hibp(password)

    # Step 2: Zxcvbn score
    zxcvbn_result = zxcvbn(password)

    # Step 3: Contextual weaknesses
    contextual_issues = detect_contextual_weaknesses(password)

    # Step 4: Score logic
    base_score = zxcvbn_result['score']

    if breach_count > 0:
        final_score = 0
    elif breach_count == -1:
        final_score = min(base_score, 3)
    else:
        penalty = min(len(contextual_issues), 2)
        final_score = max(0, base_score - penalty)

    # Recommendations
    recommendations = []
    if final_score < 2:
        recommendations.append("Your password is weak. Consider using a passphrase.")
    if breach_count > 0:
        recommendations.append(f"This password appeared in {breach_count} breaches. NEVER use it!")
    if not recommendations:
        recommendations = zxcvbn_result['feedback']['suggestions']

    return jsonify({
        'breach_count': breach_count,
        'zxcvbn_score': base_score,
        'final_score': final_score,
        'contextual_issues': contextual_issues,
        'recommendations': recommendations,
        'crack_time': zxcvbn_result['crack_times_display']['online_no_throttling_10_per_second']
    })


if __name__ == '__main__':
    app.run(ssl_context='adhoc')  # HTTPS is required for password security