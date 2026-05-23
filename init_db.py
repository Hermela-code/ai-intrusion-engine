import sqlite3

def init_db():
    conn = sqlite3.connect('idps.db')
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, source_ip TEXT, dest_ip TEXT, threat_type TEXT, risk_level TEXT, packet_count INTEGER)''')
    cursor.execute('''CREATE TABLE IF NOT EXISTS stats (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP, total_packets INTEGER, normal_count INTEGER, attack_count INTEGER)''')
    conn.commit()
    conn.close()
    print('[+] Database idps.db initialized with security and metric schemas.')

if __name__ == '__main__':
    init_db()
