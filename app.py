import sqlite3
from flask import Flask, render_template, jsonify

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('idps.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    conn = get_db_connection()
    stats_row = conn.execute('SELECT * FROM stats ORDER BY id DESC LIMIT 1').fetchone()
    alerts_rows = conn.execute('SELECT * FROM alerts ORDER BY id DESC LIMIT 10').fetchall()
    
    alerts = []
    for row in alerts_rows:
        alerts.append({
            'timestamp': row['timestamp'],
            'source_ip': row['source_ip'],
            'dest_ip': row['dest_ip'],
            'threat_type': row['threat_type'],
            'risk_level': row['risk_level'],
            'packet_count': row['packet_count']
        })
        
    conn.close()
    
    total = stats_row['total_packets'] if stats_row else 0
    normal = stats_row['normal_count'] if stats_row else 0
    attack = stats_row['attack_count'] if stats_row else 0
    
    return jsonify({
        'total_packets': total,
        'normal_count': normal,
        'attack_count': attack,
        'recent_alerts': alerts
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

