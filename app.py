from flask import Flask, render_template, request, jsonify, send_file
import json, os, threading, time, uuid
from datetime import datetime
from scanner import Scanner, Config

app = Flask(__name__)
app.config['SECRET_KEY'] = 'malvryx-scanner-2024'

# Create results directory
os.makedirs('results', exist_ok=True)

# Store active scans
active_scans = {}

class ScanThread(threading.Thread):
    def __init__(self, scan_id, target, ports, attack=False):
        threading.Thread.__init__(self)
        self.scan_id = scan_id
        self.target = target
        self.ports = ports
        self.attack = attack
        self.result = None
        self.status = 'running'
        self.progress = 0
        
    def run(self):
        try:
            config = Config()
            config.scan_ports = [int(p.strip()) for p in self.ports.split(',') if p.strip().isdigit()]
            config.attack_mode = self.attack
            
            scanner = Scanner(config)
            self.result = scanner.scan(self.target)
            
            with open(f'results/{self.scan_id}.json', 'w') as f:
                json.dump(self.result, f, indent=2)
            
            self.status = 'complete'
            self.progress = 100
        except Exception as e:
            self.status = 'error'
            self.result = {'error': str(e)}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    ports = data.get('ports', '80,443,22,21,3306,6379,8080,8443')
    attack = data.get('attack', False)
    
    if not target:
        return jsonify({'error': 'Target required'}), 400
    
    scan_id = str(uuid.uuid4())[:8]
    thread = ScanThread(scan_id, target, ports, attack)
    thread.start()
    active_scans[scan_id] = thread
    
    return jsonify({
        'scan_id': scan_id,
        'status': 'started',
        'message': f'Scanning {target}...'
    })

@app.route('/api/status/<scan_id>')
def scan_status(scan_id):
    if scan_id not in active_scans:
        if os.path.exists(f'results/{scan_id}.json'):
            with open(f'results/{scan_id}.json', 'r') as f:
                data = json.load(f)
            return jsonify({
                'status': 'complete',
                'results': data
            })
        return jsonify({'status': 'not_found'}), 404
    
    thread = active_scans[scan_id]
    
    if thread.status == 'complete' and thread.result:
        return jsonify({
            'status': 'complete',
            'progress': 100,
            'results': thread.result
        })
    
    return jsonify({
        'status': thread.status,
        'progress': thread.progress
    })

@app.route('/api/export/<scan_id>')
def export_results(scan_id):
    if not os.path.exists(f'results/{scan_id}.json'):
        return jsonify({'error': 'Results not found'}), 404
    
    with open(f'results/{scan_id}.json', 'r') as f:
        data = json.load(f)
    
    html = f"""
    <html>
    <head>
        <title>MALVRYX Scan Report</title>
        <style>
            body {{ font-family: monospace; background: #0a0a0a; color: #00ff41; padding: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #00ff41; padding: 10px; text-align: left; }}
            th {{ background: #1a1a1a; }}
            .vuln {{ color: #ff0040; }}
        </style>
    </head>
    <body>
        <h1>🔍 MALVRYX SCAN REPORT</h1>
        <p>Target: {data[0]['ip'] if data else 'N/A'}</p>
        <p>Generated: {datetime.now()}</p>
        <table>
            <tr><th>Port</th><th>Service</th><th>Banner</th><th>SNI</th><th>Vulnerable</th></tr>
    """
    
    for result in data:
        if 'port' in result and result['port']:
            vuln = '💀 YES' if result.get('vulnerable') else 'No'
            html += f"""
            <tr>
                <td>{result['port']}</td>
                <td>{result.get('service', 'Unknown')}</td>
                <td>{result.get('banner', 'N/A')[:50]}</td>
                <td>{result.get('sni', 'N/A')}</td>
                <td class="{'vuln' if result.get('vulnerable') else ''}">{vuln}</td>
            </tr>
            """
    
    html += "</table></body></html>"
    
    with open(f'results/{scan_id}.html', 'w') as f:
        f.write(html)
    
    return send_file(f'results/{scan_id}.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
