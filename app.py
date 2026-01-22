import os
import sys
import subprocess
import glob
import json
import binascii
import asyncio
import urllib3
from datetime import datetime

def install_requirements():
    PROTOBUF_VERSION = "6.33.4"
    
    required_libraries = {
        "aiohttp": "aiohttp",
        "Crypto": "pycryptodome",
        "jwt": "PyJWT",
        "blackboxprotobuf": "blackboxprotobuf",
        "colorama": "colorama",
        "google.protobuf": f"protobuf=={PROTOBUF_VERSION}"
    }
    
    missing_libraries = []
    
    try:
        import google.protobuf
        installed_version = google.protobuf.__version__
        if installed_version != PROTOBUF_VERSION:
            missing_libraries.append(f"protobuf=={PROTOBUF_VERSION}")
    except ImportError:
        missing_libraries.append(f"protobuf=={PROTOBUF_VERSION}")

    for lib_import, pkg_name in required_libraries.items():
        if "protobuf" in pkg_name: continue
        try:
            __import__(lib_import)
        except ImportError:
            missing_libraries.append(pkg_name)

    if missing_libraries:
        print(f"\n[*] Missing libraries: {', '.join(missing_libraries)}")
        print("[*] Installing requirements for Termux, please wait...\n")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_libraries])
            print("\n[+] Success! Restarting script...\n")
            os.execv(sys.executable, ['python'] + sys.argv)
        except Exception as e:
            print(f"[-] Auto-install failed: {e}")
            sys.exit(1)

install_requirements()

import aiohttp
import jwt
import blackboxprotobuf
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from colorama import Fore, Back, Style, init

init(autoreset=True)
os.environ['PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION'] = 'python'

REQUIRED_PB2_FILES = ['my_pb2', 'output_pb2', 'MajorLoginRes_pb2']

for pb2_file in REQUIRED_PB2_FILES:
    try:
        __import__(pb2_file)
    except ImportError as e:
        print(f"\n{Fore.RED}❌ CRITICAL ERROR: {pb2_file}.py is missing or corrupted!")
        print(f"{Fore.YELLOW}💡 Solution: Please ensure {pb2_file}.py is in this folder.")
        sys.exit(1)

import my_pb2
import output_pb2
import MajorLoginRes_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
PAYLOAD_FILE = "payloads.json"
ITEM_MAP_FILE = "item_map.json"

GUEST_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
MAJOR_LOGIN_URL = "https://loginbp.ggblueshark.com/MajorLogin"
GACHA_URL = "https://clientbp.ggblueshark.com/PurchaseGacha"

def load_payloads():
    if not os.path.exists(PAYLOAD_FILE):
        default = {}
        with open(PAYLOAD_FILE, "w") as f: json.dump(default, f)
        return default
    with open(PAYLOAD_FILE, "r") as f: 
        try: return json.load(f)
        except: return {}

def save_payloads(payloads):
    with open(PAYLOAD_FILE, "w") as f: json.dump(payloads, f, indent=4)

def load_item_map():
    if not os.path.exists(ITEM_MAP_FILE):
        default = {}
        with open(ITEM_MAP_FILE, "w") as f: json.dump(default, f)
        return default
    with open(ITEM_MAP_FILE, "r") as f: 
        try: return json.load(f)
        except: return {}

def save_item_map(items):
    with open(ITEM_MAP_FILE, "w") as f: json.dump(items, f, indent=4)

def banner():
    os.system('clear' if os.name == 'posix' else 'cls')
    print(f"{Fore.CYAN}{Style.BRIGHT}")
    print(r" _______  _        _______  _______  _______           _________ ")
    print(r"(  ____ \( \      (  ___  )(  ____ \(  ___  )|\     /|\__   __/")
    print(r"| (    \/| (      | (   ) || (    \/| (   ) || |   | |   ) (   ")
    print(r"| (__    | |      | (___) || |      | |   | || |   | |   | |   ")
    print(r"|  __)   | |      |  ___  || | ____ | |   | || |   | |   | |   ")
    print(r"| (      | |      | (   ) || | \_  )| |   | || |   | |   | |   ")
    print(r"| )      | (____/\| )   ( || (___) || (___) || (___) |   | |   ")
    print(r"|/       (_______/|/     \|(_______)(_______)(_______)   )_(   ")
    
    print(Fore.YELLOW + Style.BRIGHT + "="*72)
    print(Fore.MAGENTA + Style.BRIGHT + "                    FLAGOUT - The Spinner CLI")
    print(Fore.CYAN + "                Created by: Flexbase & Spideerio")
    print(Fore.GREEN + "       Join For More : Telegram : @Flexbasei & @spideerio_yt")
    print(Fore.YELLOW + Style.BRIGHT + "="*72 + "\n")

def force_exit_msg():
    print(Fore.RED + Style.BRIGHT + "\n\n🛑 [FORCE EXIT] Ctrl+C detected! Goodbye.\n")
    sys.exit()

def byte_converter(obj):
    if isinstance(obj, bytes):
        try: return obj.decode("utf-8")
        except: return obj.hex()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

def find_items_in_all_fields(data, current_item_map):
    found = []
    if isinstance(data, dict):
        for v in data.values():
            if str(v) in current_item_map: found.append((v, current_item_map[str(v)]))
            found.extend(find_items_in_all_fields(v, current_item_map))
    elif isinstance(data, list):
        for item in data:
            if str(item) in current_item_map: found.append((item, current_item_map[str(item)]))
            found.extend(find_items_in_all_fields(item, current_item_map))
    return found

def save_found_item_log(uid, pwd, nickname, acc_id, items, decoded_data):
    try:
        folder = "FOUND_ITEMS"
        if not os.path.exists(folder): os.makedirs(folder)
        file_path = os.path.join(folder, "found_accounts.json")
        detected_list = [{"item_id": i, "item_name": n} for i, n in list(set(items))]
        log_entry = {
            "save_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "account_info": {"uid": uid, "password": pwd, "nickname": nickname, "account_id": acc_id},
            "items_found": detected_list,
            "server_response_decoded": decoded_data
        }
        existing_data = []
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                try: existing_data = json.load(f)
                except: pass
        existing_data.append(log_entry)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(existing_data, f, indent=4, ensure_ascii=False, default=byte_converter)
    except: pass

def decode_gacha_response(raw_bytes, nickname, uid, pwd, acc_id, current_item_map):
    items_count = 0
    try:
        decoded_data, _ = blackboxprotobuf.decode_message(raw_bytes)
        json_output = json.dumps(decoded_data, indent=4, default=byte_converter)
        print(Fore.WHITE + json_output)
        items = find_items_in_all_fields(decoded_data, current_item_map)
        if items:
            print("\n" + Fore.YELLOW + Style.BRIGHT + "✨ " + "-"*15 + " ITEM(S) DETECTED " + "-"*15)
            unique_items = list(set(items))
            items_count = len(unique_items)
            for item_id, item_name in unique_items:
                print(Fore.GREEN + Style.BRIGHT + f"★ FOUND: {item_name} ({item_id})")
            save_found_item_log(uid, pwd, nickname, acc_id, unique_items, decoded_data)
            print(Fore.YELLOW + "-"*47)
        print(Fore.GREEN + "-" * 75)
    except: pass
    return items_count

def decode_server_error(raw_bytes):
    if not raw_bytes: return "No Response"
    try:
        text = raw_bytes.decode('utf-8', errors='ignore').strip()
        clean = ''.join(char for char in text if char.isupper() or char == '_')
        if "BR_LOTTERY_INVALID_CONSUME_TYPE" in clean: return "Not available Card/Diamond/Free Spin"
        if "BR_INVENTORY_PURCHASE_FAIL" in clean: return "Insufficient Balance or Event Expired"
        return clean if clean else "UNKNOWN_ERROR"
    except: return "UNKNOWN_ERROR"

class GachaBot:
    def __init__(self, selected_payload_bytes, current_item_map):
        self.successful = 0
        self.failed = 0
        self.processed = 0
        self.total = 0
        self.items_found_count = 0
        self.payload = selected_payload_bytes
        self.item_map = current_item_map

    def encrypt_message(self, plaintext):
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return cipher.encrypt(pad(plaintext, AES.block_size))

    async def get_guest_token(self, session, uid, password):
        payload = {'uid': uid, 'password': password, 'response_type': "token", 'client_type': "2", 'client_id': "100067", 'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"}
        try:
            async with session.post(GUEST_URL, data=payload, ssl=False, timeout=10) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get('access_token'), data.get('open_id')
                return None, None
        except: return None, None

    async def get_major_jwt(self, session, access_token, open_id):
        platforms = [8, 3, 4, 6]
        headers = {"User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)", "Connection": "Keep-Alive", "Accept-Encoding": "gzip", "Content-Type": "application/octet-stream", "Expect": "100-continue", "X-Unity-Version": "2018.4.11f1", "X-GA": "v1 1", "ReleaseVersion": "OB52"}
        for platform_type in platforms:
            try:
                game_data = my_pb2.GameData()
                game_data.timestamp, game_data.game_name, game_data.game_version, game_data.version_code = "2026-1-05 18:15:32", "free fire", 1, "1.120.2"
                game_data.os_info, game_data.device_type, game_data.network_provider, game_data.connection_type = "Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)", "Handheld", "Verizon Wireless", "WIFI"
                game_data.screen_width, game_data.screen_height, game_data.dpi = 1280, 960, "240"
                game_data.cpu_info, game_data.total_ram, game_data.gpu_name, game_data.gpu_version = "ARMv7 VFPv3 NEON VMH | 2400 | 4", 5951, "Adreno (TM) 640", "OpenGL ES 3.0"
                game_data.user_id, game_data.ip_address, game_data.language = "Google|74b585a9-0268-4ad3-8f36-ef41d2e53610", "172.190.111.97", "en"
                game_data.open_id, game_data.access_token, game_data.platform_type = open_id, access_token, platform_type
                game_data.field_99, game_data.field_100 = str(platform_type), str(platform_type)

                serialized_data = game_data.SerializeToString()
                encrypted = self.encrypt_message(serialized_data)
                edata = bytes.fromhex(binascii.hexlify(encrypted).decode('utf-8'))
                async with session.post(MAJOR_LOGIN_URL, data=edata, headers=headers, ssl=False, timeout=10) as resp:
                    if resp.status == 200:
                        content = await resp.read()
                        res_msg = output_pb2.Garena_420()
                        res_msg.ParseFromString(content)
                        data_dict = {f.name: getattr(res_msg, f.name) for f in res_msg.DESCRIPTOR.fields if f.name == "token"}
                        if data_dict and "token" in data_dict: return data_dict["token"]
            except: continue
        return None

    async def purchase_gacha(self, session, jwt_token, uid, pwd, nickname, acc_id):
        headers = {'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)", 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/octet-stream", 'Authorization': f"Bearer {jwt_token}", 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1", 'ReleaseVersion': "OB52"}
        try:
            async with session.post(GACHA_URL, headers=headers, data=self.payload, ssl=False, timeout=12) as resp:
                response_content = await resp.read()
                self.processed += 1
                if resp.status == 200:
                    print(Fore.GREEN + Style.BRIGHT + f"[{self.processed}/{self.total}] 🎰 [SUCCESS] {nickname} (ID: {acc_id})")
                    print(Fore.CYAN + f"   🔑 UID: {uid} | PASS: {pwd}"); print(Fore.GREEN + "-" * 75)
                    count = decode_gacha_response(response_content, nickname, uid, pwd, acc_id, self.item_map)
                    self.items_found_count += count
                    return True
                else:
                    err = decode_server_error(response_content)
                    print(Fore.RED + f"[{self.processed}/{self.total}] 🎰 [FAILED] {nickname} (ID: {acc_id}) | Status: {resp.status}")
                    print(Fore.CYAN + f"   🔑 UID: {uid} | PASS: {pwd}")
                    print(Fore.YELLOW + f"   ⚠️ Server Error: {err}"); print(Fore.RED + "-" * 75)
                    return False
        except: return False

    async def process_account(self, session, account):
        uid, pwd = account['uid'], account['password']
        acc_token, open_id = await self.get_guest_token(session, uid, pwd)
        if not acc_token: self.failed += 1; return
        jwt_token = await self.get_major_jwt(session, acc_token, open_id)
        if not jwt_token: self.failed += 1; return
        try:
            decoded = jwt.decode(jwt_token, options={"verify_signature": False})
            acc_id, nickname = decoded.get("account_id", "N/A"), decoded.get("nickname", "Unknown")
        except: acc_id, nickname = "N/A", "Unknown"
        if await self.purchase_gacha(session, jwt_token, uid, pwd, nickname, acc_id): self.successful += 1
        else: self.failed += 1

def parse_accounts(filepath):
    accounts = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read().strip()
        data = json.loads(content)
        if isinstance(data, list):
            for i in data:
                u, p = i.get('uid') or i.get('user'), i.get('password') or i.get('pass')
                if u and p and str(u).isdigit(): accounts.append({'uid': str(u), 'password': str(p)})
    except:
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    parts = line.strip().replace('|', ':').split(':')
                    if len(parts) >= 2 and parts[0].isdigit():
                        accounts.append({'uid': parts[0], 'password': parts[1]})
        except: pass
    return accounts

async def main_menu():
    while True:
        try:
            banner()
            print(Fore.WHITE + "1. Action")
            print(Fore.WHITE + "2. Add Payload")
            print(Fore.WHITE + "3. View and Remove Payload")
            print(Fore.WHITE + "4. Help")
            print(Fore.WHITE + "5. Manage Item Map")
            print(Fore.RED + "0. Exit")
            
            choice = input(Fore.CYAN + "\n🎯 Choice: ").strip()

            if choice == '0':
                print(Fore.GREEN + "\n👋 Thank you for using FLAGOUT! Goodbye.")
                sys.exit()

            elif choice == '4':
                banner()
                print(Fore.YELLOW + "📖 HELP:")
                print("1. Action: Load files and spin.")
                print("2. Add Payload: Save hex string.")
                print("3. View/Remove: Manage payloads.")
                print("5. Item Map: Set IDs to track.")
                input("\nEnter...")

            elif choice == '2':
                hex_d = input("Hex: ").strip(); name = input("Name: ").strip()
                if hex_d and name:
                    p = load_payloads(); p[name] = hex_d; save_payloads(p); print("✅ Saved!")
                input("Enter...")

            elif choice == '3':
                p = load_payloads(); p_n = list(p.keys())
                for i, n in enumerate(p_n, 1): print(f"  {i}. {n}")
                print(Fore.RED + "  0. Back")
                rem = input("\nSelect: ").strip()
                if rem != '0' and rem.isdigit() and 0 < int(rem) <= len(p_n):
                    del p[p_n[int(rem)-1]]; save_payloads(p); print("🗑️ Removed!")
                input("Enter...")

            elif choice == '5':
                while True:
                    banner()
                    print(Fore.YELLOW + "MANAGE ITEM MAPPING")
                    print(Fore.WHITE + "1. View Current Item Mapping")
                    print(Fore.WHITE + "2. Add New Item Mapping")
                    print(Fore.WHITE + "3. Remove Existing Mapping")
                    print(Fore.RED + "0. Back to Main Menu")
                    
                    sub = input(Fore.CYAN + "\n🎯 Choice: ").strip()
                    it = load_item_map()
                    if sub == '0': break
                    elif sub == '1':
                        for k, v in it.items(): print(f"  ID: {k} -> {v}")
                        input("\nEnter to continue...")
                    elif sub == '2':
                        kid = input("Enter Item ID: "); knm = input("Enter Item Name: ")
                        if kid and knm: it[kid] = knm; save_item_map(it); print("✅ Added!")
                        input("Enter...")
                    elif sub == '3':
                        ids = list(it.keys())
                        for i, x in enumerate(ids, 1): print(f"  {i}. {x} ({it[x]})")
                        print(Fore.RED + "  0. Back")
                        ri = input("\nSelect number to remove: ").strip()
                        if ri != '0' and ri.isdigit() and 0 < int(ri) <= len(ids):
                            del it[ids[int(ri)-1]]; save_item_map(it); print("🗑️ Removed!")
                        input("Enter...")

            elif choice == '1':
                all_f = glob.glob("*.txt") + glob.glob("*.json")
                exclude = ['activation_log.txt', 'success-BD.json', 'failed-BD.json', 'decoded_output.txt', 'payloads.json', 'item_map.json']
                files = [f for f in all_f if f not in exclude and "✅" not in f]
                if not files: print(Fore.RED + "No files!"); input("Enter..."); continue
                
                for i, f in enumerate(files, 1): print(f"  {i}. {f}")
                print("  all. Process all | 0. Back")
                f_choice = input("\n🎯 Select: ").strip().lower()
                if f_choice == '0': continue
                
                t_files = files if f_choice == 'all' else [files[int(f_choice)-1]] if (f_choice.isdigit() and int(f_choice) <= len(files)) else []
                if not t_files: continue

                p = load_payloads()
                if not p: print(Fore.RED + "Add payload first!"); input("Enter..."); continue
                p_n = list(p.keys())
                for i, n in enumerate(p_n, 1): print(f"  {i}. {n}")
                px = input("\n🎯 Select Payload: ").strip()
                if not (px.isdigit() and 0 < int(px) <= len(p_n)): continue
                
                p_bytes = binascii.unhexlify(p[p_n[int(px)-1]].replace(" ", ""))
                bot = GachaBot(p_bytes, load_item_map())
                
                async with aiohttp.ClientSession() as session:
                    for f in t_files:
                        accs = parse_accounts(f)
                        if not accs: continue
                        bot.total = len(accs); bot.processed = 0
                        print(Fore.GREEN + f"\n🚀 File: {f}\n")
                        for acc in accs: await bot.process_account(session, acc)
                        n, e = os.path.splitext(f); os.rename(f, f"{n} ✅{e}")
                
                print(Fore.GREEN + Style.BRIGHT + f"\n✅ Success: {bot.successful} | Failed: {bot.failed} | Items: {bot.items_found_count}")
                input("\nEnter...")
        
        except KeyboardInterrupt: force_exit_msg()

if __name__ == "__main__":
    try: asyncio.run(main_menu())
    except KeyboardInterrupt: force_exit_msg()