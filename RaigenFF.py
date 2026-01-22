# code made by @raigenffofc telegram channel
import os
import sys
import glob
import json
import binascii
import asyncio
import urllib3
import base64
from datetime import datetime
from flask import Flask, request, jsonify, Response, render_template_string, stream_with_context
# CODE BY @RAIGENFFOFC
# CODE BY @RAIGENFFOFC


# --- Encryption Logic ---
def _d(s):
    try: return base64.b64decode(s).decode('utf-8')
    except: return ""

_T = "UkFJR0VOIEZGIExVQ0sgUk9ZQUwgU1BJTiBQUk8="
_C = "Y29kZSBtYWRlIGJ5IEByYWlnZW5mZm9mYyB0ZWxlZ3JhbSBjaGFubmVs"
_L = "aHR0cHM6Ly90Lm1lL3JhaWdlbmZmb2Zj"
_S = "UkFJR0VOIEZG"

# --- Flask Setup ---
app = Flask(__name__)
app.secret_key = "raigen_ff_pro_max_v10_final_fix"

# --- Libraries ---
import aiohttp
import jwt
import blackboxprotobuf
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

REQUIRED_PB2_FILES = ['my_pb2', 'output_pb2', 'MajorLoginRes_pb2']
for pb2_file in REQUIRED_PB2_FILES:
    try: __import__(pb2_file)
    except ImportError: print(f"CRITICAL ERROR: {pb2_file}.py is missing! {_d(_C)}")

import my_pb2
import output_pb2
import MajorLoginRes_pb2

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- Config ---
AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV = b'6oyZDr22E3ychjM%'
PAYLOAD_FILE = "payloads.json"
ITEM_MAP_FILE = "item_map.json"
WIN_FILE = "SpinWinGojo.txt"

GUEST_URL = "https://100067.connect.garena.com/oauth/guest/token/grant"
MAJOR_LOGIN_URL = "https://loginbp.ggblueshark.com/MajorLogin"
GACHA_URL = "https://clientbp.ggblueshark.com/PurchaseGacha"

# --- HTML Template ---
HTML_TEMPLATE = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>{_d(_T)}</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600;700&display=swap" rel="stylesheet">
    <style>
        :root {{ --bg-color: #0f172a; --sidebar-bg: #1e293b; --accent: #8b5cf6; --success: #10b981; --danger: #ef4444; --warning: #f59e0b; --info: #3b82f6; --text: #e2e8f0; --table-header: #334155; --telegram: #0088cc; }}
        * {{ box-sizing: border-box; }}
        body {{ margin: 0; padding: 0; background-color: var(--bg-color); color: var(--text); font-family: 'Poppins', sans-serif; height: 100vh; display: flex; flex-direction: column; }}
        
        .app-container {{ display: flex; flex: 1; overflow: hidden; }}
        .sidebar {{ width: 320px; background: var(--sidebar-bg); padding: 15px; display: flex; flex-direction: column; border-right: 1px solid #334155; overflow-y: auto; z-index: 10; }}
        .main-content {{ flex: 1; padding: 20px; display: flex; flex-direction: column; overflow: hidden; position: relative; }}

        @media (max-width: 768px) {{
            .app-container {{ flex-direction: column; overflow-y: auto; }}
            .sidebar {{ width: 100%; height: auto; border-right: none; border-bottom: 2px solid #334155; padding-bottom: 20px; flex: none; }}
            .main-content {{ height: auto; overflow: visible; padding: 10px; flex: none; }}
            body {{ height: auto; overflow-y: auto; }}
            .table-wrapper {{ overflow-x: auto; }}
            .table-header, .table-row {{ min-width: 600px; }}
        }}

        h1 {{ color: var(--accent); font-size: 1.3rem; margin: 0 0 10px 0; text-align: center; letter-spacing: 1px; line-height: 1.4; }}
        .section-header {{ font-size: 0.75rem; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-top: 15px; margin-bottom: 8px; border-bottom: 1px solid #334155; padding-bottom: 4px; font-weight: bold; }}
        
        input, select, textarea {{ width: 100%; background: #0f172a; border: 1px solid #475569; color: #fff; padding: 10px; border-radius: 8px; margin-bottom: 10px; font-family: inherit; font-size: 0.9rem; }}
        input:focus, select:focus, textarea:focus {{ border-color: var(--accent); outline: none; }}
        
        .btn {{ border: none; padding: 12px; border-radius: 8px; cursor: pointer; font-weight: 600; width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px; transition: 0.2s; font-size: 0.9rem; margin-bottom: 5px; }}
        .btn-primary {{ background: linear-gradient(135deg, #8b5cf6, #6366f1); color: white; }}
        .btn-danger {{ background: var(--danger); color: white; }}
        .btn-upload {{ background: #334155; color: white; border: 1px dashed #64748b; }}
        .btn-sm {{ padding: 5px 10px; font-size: 0.75rem; width: auto; background: #ef4444; color: white; border-radius: 4px; margin: 0; }}
        
        .btn-telegram {{ background: var(--telegram); color: white; margin-bottom: 15px; text-decoration: none; box-shadow: 0 4px 6px rgba(0, 136, 204, 0.3); }}
        .btn-telegram:hover {{ background: #0077b5; transform: translateY(-2px); }}

        .file-list-item {{ display: flex; justify-content: space-between; align-items: center; background: #0f172a; padding: 8px; border-radius: 4px; border: 1px solid #334155; margin-bottom: 5px; font-size: 0.85rem; }}
        .file-name {{ cursor: pointer; color: #60a5fa; text-decoration: underline; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; max-width:160px; }}
        .file-name:hover {{ color: #93c5fd; }}
        
        .stats-container {{ display: flex; gap: 10px; margin-bottom: 15px; }}
        .stat-card {{ flex: 1; background: var(--sidebar-bg); padding: 15px; border-radius: 10px; border: 1px solid #334155; display: flex; align-items: center; justify-content: space-between; }}
        .stat-info h3 {{ margin: 0; font-size: 1.5rem; color: var(--accent); }}
        .stat-info p {{ margin: 0; color: #94a3b8; font-size: 0.75rem; }}
        .win-card h3 {{ color: var(--warning); }}
        
        .table-wrapper {{ flex: 1; background: var(--sidebar-bg); border-radius: 10px; border: 1px solid #334155; overflow: hidden; display: flex; flex-direction: column; min-height: 300px; }}
        .table-header {{ padding: 12px; background: var(--table-header); font-weight: bold; display: grid; grid-template-columns: 0.5fr 1.5fr 1.5fr 1fr 2fr; gap: 10px; font-size: 0.8rem; border-bottom: 1px solid #475569; }}
        .table-body {{ flex: 1; overflow-y: auto; padding: 0; }}
        .table-row {{ display: grid; grid-template-columns: 0.5fr 1.5fr 1.5fr 1fr 2fr; gap: 10px; padding: 10px 12px; border-bottom: 1px solid #334155; align-items: center; font-size: 0.8rem; }}
        .table-row:nth-child(even) {{ background: #1e293b; }}
        .table-row:nth-child(odd) {{ background: #182335; }}
        
        .badge {{ padding: 3px 6px; border-radius: 3px; font-size: 0.65rem; font-weight: bold; text-transform: uppercase; text-align: center; }}
        .badge-win {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid #f59e0b; }}
        .badge-success {{ background: rgba(16, 185, 129, 0.2); color: #34d399; border: 1px solid #10b981; }}
        .badge-fail {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid #ef4444; }}
        .badge-already {{ background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid #3b82f6; }}

        .spinner {{ display: none; animation: spin 1s linear infinite; }}
        @keyframes spin {{ 100% {{ transform: rotate(360deg); }} }}

        .modal {{ display: none; position: fixed; z-index: 100; left: 0; top: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.8); backdrop-filter: blur(5px); }}
        .modal-content {{ background-color: #1e293b; margin: 10% auto; padding: 20px; border: 1px solid #888; width: 90%; max-width: 600px; border-radius: 10px; position: relative; color: #fff; box-shadow: 0 0 20px rgba(139, 92, 246, 0.3); display: flex; flex-direction: column; }}
        .close-modal {{ color: #aaa; align-self: flex-end; font-size: 28px; font-weight: bold; cursor: pointer; }}
        .close-modal:hover {{ color: #fff; }}
        #modalTitle {{ color: var(--accent); margin-top: -10px; margin-bottom: 10px; }}
        #modalBody {{ width: 100%; height: 350px; background: #0f172a; border: 1px solid #334155; color: #cbd5e1; padding: 10px; font-family: monospace; resize: none; border-radius: 5px; outline: none; }}
    </style>
</head>
<body>
    <div class="app-container">
        <div class="sidebar">
            <h1>{_d(_T)}</h1>
            <a href="{_d(_L)}" target="_blank" class="btn btn-telegram">
                <i class="fa-brands fa-telegram"></i> {_d(_S)}
            </a>

            <div class="section-header"><i class="fa-solid fa-cloud-upload"></i> Upload Account JSON</div>
            <form action="/upload_file" method="POST" enctype="multipart/form-data" style="display:flex; gap:5px;">
                <input type="file" name="file" accept=".json,.txt" required style="padding: 8px; font-size: 0.8rem;">
                <button type="submit" class="btn btn-upload" style="width: auto;"><i class="fa-solid fa-arrow-up"></i></button>
            </form>

            <div class="section-header"><i class="fa-solid fa-play"></i> Run Attack</div>
            <form id="runForm">
                <select name="payload_name" required>
                    <option value="" disabled selected>Select Payload</option>
                    {{% for name in payloads %}}
                    <option value="{{{{ name }}}}">{{{{ name }}}}</option>
                    {{% endfor %}}
                </select>
                <select id="fileSelect" name="file_selection" onchange="toggleManualInput()">
                    <option value="manual">Manual Input</option>
                    {{% for file in files %}}
                    <option value="{{{{ file }}}}">{{{{ file }}}}</option>
                    {{% endfor %}}
                </select>
                <div id="manualInputBox">
                    <textarea name="accounts_manual" rows="3" placeholder="UID:PASS"></textarea>
                </div>
                <button type="submit" class="btn btn-primary" id="runBtn">
                    START <i class="fa-solid fa-circle-notch spinner" id="loadingSpinner"></i>
                </button>
                <button type="button" class="btn btn-danger" id="stopBtn" style="display: none;" onclick="location.reload()">
                     STOP
                </button>
            </form>

            <div class="section-header"><i class="fa-solid fa-folder"></i> Manage Files</div>
            <div style="max-height:200px; overflow-y:auto;">
                {{% for file in files %}}
                <div class="file-list-item">
                    <span class="file-name" onclick="viewFile('{{{{ file }}}}')"><i class="fa-solid fa-file-alt"></i> {{{{ file }}}}</span>
                    <button onclick="deleteFile('{{{{ file }}}}')" class="btn-sm"><i class="fa-solid fa-trash"></i></button>
                </div>
                {{% endfor %}}
            </div>

            <div class="section-header"><i class="fa-solid fa-code"></i> Add Payload</div>
            <form id="addPayloadForm">
                <input type="text" name="name" placeholder="Name" required>
                <input type="text" name="hex" placeholder="Hex Code" required>
                <button type="submit" class="btn btn-primary" style="background:#475569; padding:8px;">+ Save</button>
            </form>
            
            <div style="margin-top:20px; text-align:center; font-size:0.6rem; color:#64748b;">
                {_d(_C)}
            </div>
        </div>

        <div class="main-content">
            <div class="stats-container">
                <div class="stat-card">
                    <div class="stat-info"><h3 id="countTotal">0</h3><p>Checked</p></div>
                    <i class="fa-solid fa-list-check fa-lg" style="color:#475569;"></i>
                </div>
                <div class="stat-card win-card" style="border-color: #f59e0b;">
                    <div class="stat-info"><h3 id="countWins">0</h3><p>Wins</p></div>
                    <i class="fa-solid fa-trophy fa-lg" style="color:#f59e0b;"></i>
                </div>
            </div>

            <div class="table-wrapper">
                <div class="table-header">
                    <div>#</div><div>UID</div><div>Name</div><div>Status</div><div>Result</div>
                </div>
                <div class="table-body" id="resultTableBody">
                    <div style="padding:30px; text-align:center; color:#64748b;" id="placeholder">
                        {_d(_T)}<br>Select file & start.
                    </div>
                </div>
            </div>
        </div>
    </div>

    <div id="fileModal" class="modal">
        <div class="modal-content">
            <span class="close-modal" onclick="closeModal()">&times;</span>
            <h3 id="modalTitle">File Viewer</h3>
            <textarea id="modalBody" readonly></textarea>
        </div>
    </div>

    <script>
        function toggleManualInput() {{
            const val = document.getElementById('fileSelect').value;
            document.getElementById('manualInputBox').style.display = val === 'manual' ? 'block' : 'none';
        }}

        async function viewFile(filename) {{
            const modal = document.getElementById("fileModal");
            const title = document.getElementById("modalTitle");
            const body = document.getElementById("modalBody");
            title.innerText = filename; body.value = "Loading..."; modal.style.display = "block";
            try {{ const res = await fetch('/view_file/' + filename); const text = await res.text(); body.value = text; }}
            catch (e) {{ body.value = "Error loading file."; }}
        }}

        function closeModal() {{ document.getElementById("fileModal").style.display = "none"; }}
        window.onclick = function(e) {{ if(e.target == document.getElementById("fileModal")) closeModal(); }}

        async function deleteFile(filename) {{
            if(!confirm('Delete ' + filename + '?')) return;
            await fetch('/delete_file/' + filename); location.reload();
        }}

        document.getElementById('addPayloadForm').addEventListener('submit', async (e) => {{
            e.preventDefault(); await fetch('/add_payload', {{ method: 'POST', body: new FormData(e.target) }}); location.reload();
        }});

        document.getElementById('runForm').addEventListener('submit', async (e) => {{
            e.preventDefault();
            document.getElementById('runBtn').style.display = 'none';
            document.getElementById('stopBtn').style.display = 'flex';
            document.getElementById('placeholder').style.display = 'none';
            document.getElementById('resultTableBody').innerHTML = '';
            
            let total = 0, wins = 0;
            const maxLogs = 10;
            const response = await fetch('/run_bot', {{ method: 'POST', body: new FormData(e.target) }});
            const reader = response.body.getReader();
            const decoder = new TextDecoder();

            while (true) {{
                const {{ done, value }} = await reader.read();
                if (done) break;
                const chunk = decoder.decode(value);
                const lines = chunk.split('\\n');
                lines.forEach(line => {{
                    if (line.includes('|')) {{
                        const parts = line.split('|');
                        if(parts.length >= 4) {{
                            total++;
                            document.getElementById('countTotal').innerText = total;
                            const type = parts[0], uid = parts[1], name = parts[2], msg = parts[3];
                            let badge = 'badge-fail', rowStyle = '';
                            if (type === 'WIN') {{
                                wins++; document.getElementById('countWins').innerText = wins;
                                badge = 'badge-win'; rowStyle = 'background: rgba(245, 158, 11, 0.15);';
                            }} else if (type === 'SUCCESS') {{ badge = 'badge-success'; 
                            }} else if (type === 'ALREADY') {{ badge = 'badge-already'; rowStyle = 'background: rgba(59, 130, 246, 0.1);'; }}
                            
                            const html = `<div class="table-row" style="${{rowStyle}}"><div>${{total}}</div><div style="font-family:monospace; color:#cbd5e1;">${{uid}}</div><div style="font-weight:bold; color:#fff;">${{name}}</div><div><span class="badge ${{badge}}">${{type}}</span></div><div style="font-size:0.75rem; color:#ccc;">${{msg}}</div></div>`;
                            const container = document.getElementById('resultTableBody');
                            container.insertAdjacentHTML('afterbegin', html);
                            if (container.children.length > maxLogs) {{ container.lastElementChild.remove(); }}
                        }}
                    }}
                }});
            }}
            document.getElementById('runBtn').style.display = 'flex';
            document.getElementById('stopBtn').style.display = 'none';
        }});
    </script>
</body>
</html>
"""

# --- Helpers ---
def load_json(fp):
    if not os.path.exists(fp):
        with open(fp, "w") as f: json.dump({}, f)
        return {}
    try:
        with open(fp, "r") as f: return json.load(f)
    except: return {}

def save_json(fp, data):
    with open(fp, "w") as f: json.dump(data, f, indent=4)

def get_account_files():
    all_files = glob.glob("*.json") + glob.glob("*.txt")
    exclude = ['payloads.json', 'item_map.json', 'raigenffweb.py', 'requirements.txt'] 
    return [f for f in all_files if f not in exclude and "✅" not in f]

def decode_error(raw):
    if not raw: return "No Response"
    try:
        text = raw.decode('utf-8', errors='ignore').strip()
        clean = ''.join(c for c in text if c.isprintable())
        if "BR_LOTTERY_INVALID_CONSUME_TYPE" in clean: return "ALREADY_SPIN"
        if "BR_INVENTORY_PURCHASE_FAIL" in clean: return "Insufficient Balance"
        return clean if clean else "Unknown Error"
    except: return "Decode Error"

def find_items(data, item_map):
    found = []
    if isinstance(data, dict):
        for v in data.values():
            if str(v) in item_map: found.append((str(v), item_map[str(v)]))
            found.extend(find_items(v, item_map))
    elif isinstance(data, list):
        for item in data:
            if str(item) in item_map: found.append((str(item), item_map[str(item)]))
            found.extend(find_items(item, item_map))
    return found

def check_history(uid):
    if os.path.exists(WIN_FILE):
        try:
            with open(WIN_FILE, 'r', encoding='utf-8') as f:
                if uid in f.read(): return True
        except: pass
    return False

# --- Bot Logic ---
class GachaBot:
    def __init__(self, payload, item_map):
        self.payload = payload
        self.item_map = item_map

    def encrypt(self, plain):
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return cipher.encrypt(pad(plain, AES.block_size))

    async def get_guest(self, session, uid, pwd):
        pl = {'uid': uid, 'password': pwd, 'response_type': "token", 'client_type': "2", 'client_id': "100067", 'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"}
        try:
            async with session.post(GUEST_URL, data=pl, ssl=False, timeout=8) as r:
                if r.status == 200:
                    d = await r.json()
                    return d.get('access_token'), d.get('open_id')
        except: pass
        return None, None

    async def get_jwt(self, session, token, open_id):
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "Content-Type": "application/octet-stream",
            "Expect": "100-continue",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB52"
        }
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        platforms = [8, 3, 4, 6]
        for platform_type in platforms:
            try:
                game_data = my_pb2.GameData()
                game_data.timestamp = current_time 
                game_data.game_name = "free fire"
                game_data.game_version = 1
                game_data.version_code = "1.120.2"
                game_data.os_info = "Android OS 9"
                game_data.device_type = "Handheld"
                game_data.network_provider = "WIFI"
                game_data.connection_type = "WIFI"
                game_data.screen_width = 1280
                game_data.screen_height = 960
                game_data.dpi = "240"
                game_data.cpu_info = "ARMv7 VFPv3 NEON VMH | 2400 | 4"
                game_data.total_ram = 5951
                game_data.gpu_name = "Adreno (TM) 640"
                game_data.gpu_version = "OpenGL ES 3.0"
                game_data.user_id = "Google|74b585a9"
                game_data.ip_address = "127.0.0.1"
                game_data.language = "en"
                game_data.open_id = open_id
                game_data.access_token = token
                game_data.platform_type = platform_type
                game_data.field_99 = str(platform_type)
                game_data.field_100 = str(platform_type)
                
                edata = bytes.fromhex(binascii.hexlify(self.encrypt(game_data.SerializeToString())).decode())
                
                async with session.post(MAJOR_LOGIN_URL, data=edata, headers=headers, ssl=False, timeout=10) as r:
                    if r.status == 200:
                        c = await r.read()
                        msg = output_pb2.Garena_420()
                        msg.ParseFromString(c)
                        for f in msg.DESCRIPTOR.fields:
                            if f.name == "token": return getattr(msg, f.name)
            except: continue
        return None

    async def spin(self, session, uid, pwd):
        if check_history(uid):
            yield f"ALREADY|{uid}|Unknown|Saved in History\n"
            return

        gt, oid = await self.get_guest(session, uid, pwd)
        if not gt:
            yield f"FAIL|{uid}|Unknown|Guest Token Error\n"
            return

        jwt_token = await self.get_jwt(session, gt, oid)
        if not jwt_token:
            yield f"FAIL|{uid}|Unknown|Login/JWT Failed\n"
            return

        try:
            dec = jwt.decode(jwt_token, options={"verify_signature": False})
            nick = dec.get("nickname", "Unknown")
        except: nick = "Unknown"

        headers = {
            'User-Agent': "Dalvik/2.1.0",
            'Connection': "Keep-Alive",
            'Accept-Encoding': "gzip",
            'Content-Type': "application/octet-stream",
            'Authorization': f"Bearer {jwt_token}",
            'X-Unity-Version': "2018.4.11f1",
            'X-GA': "v1 1",
            'ReleaseVersion': "OB52"
        }

        try:
            async with session.post(GACHA_URL, headers=headers, data=self.payload, ssl=False, timeout=12) as r:
                content = await r.read()
                if r.status == 200:
                    try:
                        ddata, _ = blackboxprotobuf.decode_message(content)
                        wins = find_items(ddata, self.item_map)
                        if wins:
                            names = ", ".join([f"{n}" for i, n in list(set(wins))])
                            with open(WIN_FILE, "a", encoding="utf-8") as f:
                                f.write(f"UID: {uid} | PASS: {pwd} | Nick: {nick} | Item: {names}\n")
                            yield f"WIN|{uid}|{nick}|{names}\n"
                        else:
                            yield f"SUCCESS|{uid}|{nick}|Success\n"
                    except:
                        yield f"SUCCESS|{uid}|{nick}|Success\n"
                else:
                    err = decode_error(content)
                    if err == "ALREADY_SPIN": yield f"ALREADY|{uid}|{nick}|Already Spin\n"
                    else: yield f"FAIL|{uid}|{nick}|{err}\n"
        except Exception as e:
            yield f"FAIL|{uid}|{nick}|Net Error\n"

# --- Routes ---
@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE, 
        payloads=load_json(PAYLOAD_FILE),
        items=load_json(ITEM_MAP_FILE),
        files=get_account_files())

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if 'file' not in request.files: return "No file selected"
    file = request.files['file']
    if file.filename == '': return "No filename"
    if file: file.save(os.path.join(os.getcwd(), file.filename))
    return "<script>window.location.href='/';</script>"

@app.route('/delete_file/<filename>')
def delete_file(filename):
    if filename in ['app.py', 'raigenffweb.py', 'requirements.txt', 'payloads.json', 'item_map.json']:
        return "System file cannot be deleted!"
    if os.path.exists(filename): os.remove(filename)
    return jsonify({"status":"ok"})

@app.route('/view_file/<filename>')
def view_file(filename):
    if filename in ['raigenffweb.py', 'app.py'] or '..' in filename: return "Access Denied"
    if os.path.exists(filename):
        try: 
            with open(filename, 'r', encoding='utf-8') as f: return f.read()
        except: return "Error reading file."
    return "File not found"

@app.route('/add_payload', methods=['POST'])
def add_pl():
    n, h = request.form.get('name'), request.form.get('hex')
    if n and h: p = load_json(PAYLOAD_FILE); p[n] = h; save_json(PAYLOAD_FILE, p)
    return jsonify({"status":"ok"})

@app.route('/run_bot', methods=['POST'])
def run():
    pname = request.form.get('payload_name')
    fsel = request.form.get('file_selection')
    manual = request.form.get('accounts_manual')
    pdata = load_json(PAYLOAD_FILE)
    if pname not in pdata: return "FAIL|SYSTEM|ERROR|Payload Not Found\n"
    try: pbytes = binascii.unhexlify(pdata[pname].replace(" ", ""))
    except: return "FAIL|SYSTEM|ERROR|Invalid Hex\n"

    accs = []
    if fsel and fsel != 'manual' and os.path.exists(fsel):
        try:
            if fsel.endswith('.json'):
                d = json.load(open(fsel))
                for x in d: accs.append((str(x.get('uid', '')), str(x.get('password', ''))))
            else:
                for l in open(fsel).read().splitlines():
                    p = l.replace('|', ':').split(':')
                    if len(p)>=2: accs.append((p[0].strip(), p[1].strip()))
        except: pass
    elif manual:
        for l in manual.splitlines():
            p = l.replace('|', ':').split(':')
            if len(p)>=2: accs.append((p[0].strip(), p[1].strip()))

    if not accs: return "FAIL|SYSTEM|ERROR|No Accounts Found\n"
    imap = load_json(ITEM_MAP_FILE)

    def generate():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        async def run_logic():
            bot = GachaBot(pbytes, imap)
            async with aiohttp.ClientSession() as sess:
                for u, p in accs:
                    async for log in bot.spin(sess, u, p):
                        yield log
        
        runner = run_logic()
        try:
            while True:
                try: 
                    chunk = loop.run_until_complete(runner.__anext__())
                    yield chunk
                except StopAsyncIteration: 
                    break
        except GeneratorExit:
            pass
        except Exception:
            pass
        finally:
            try: loop.run_until_complete(runner.aclose())
            except: pass
            try: loop.close()
            except: pass

    return Response(stream_with_context(generate()), mimetype='text/plain')

if __name__ == '__main__':
    print("Mobile Web Server Running...")
    print("Open in Browser: http://127.0.0.1:5000")
    # code made by @raigenffofc telegram channel
    app.run(host='0.0.0.0', port=5000, debug=True)
