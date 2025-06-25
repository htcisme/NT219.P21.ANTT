from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import json
import requests
import threading
import time
from datetime import datetime, timedelta
import sqlite3
import os
from collections import defaultdict, deque
import logging

app = Flask(__name__)
app.config['SECRET_KEY'] = 'monitor_secret_key_2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Configure logging
logging.basicConfig(level=logging.INFO)

class AccessControlMonitor:
    def __init__(self):
        self.server_url = "http://localhost:5000"
        self.card_url = "http://localhost:5001"
        
        # Real-time data storage
        self.access_logs = deque(maxlen=1000)  # Last 1000 access attempts
        self.system_metrics = {
            'server_status': 'unknown',
            'card_status': 'unknown',
            'active_sessions': 0,
            'total_users': 0,
            'uptime': 0
        }
        
        # Statistics
        self.stats = {
            'total_attempts': 0,
            'successful_attempts': 0,
            'failed_attempts': 0,
            'unique_users': set(),
            'popular_zones': defaultdict(int),
            'hourly_stats': defaultdict(int),
            'daily_stats': defaultdict(int)
        }
        
        # Alerts
        self.alerts = deque(maxlen=100)
        self.alert_thresholds = {
            'failed_attempts_per_minute': 10,
            'response_time_ms': 5000,
            'concurrent_failures': 5
        }
        
        # Initialize database
        self.init_database()
        
        # Start monitoring threads
        self.start_monitoring()
    
    def init_database(self):
        """Initialize SQLite database for persistent storage"""
        self.db_path = 'access_monitor.db'
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Access logs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS access_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    reader_id TEXT,
                    user_id TEXT,
                    user_name TEXT,
                    decision TEXT,
                    reason TEXT,
                    access_zone TEXT,
                    response_time REAL,
                    biometric_used BOOLEAN,
                    ip_address TEXT
                )
            ''')
            
            # System metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    metric_name TEXT,
                    metric_value TEXT,
                    details TEXT
                )
            ''')
            
            # Security events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT,
                    severity TEXT,
                    description TEXT,
                    source_ip TEXT,
                    user_id TEXT,
                    additional_data TEXT
                )
            ''')
            
            conn.commit()
            logging.info("Database initialized successfully")
    
    def start_monitoring(self):
        """Start background monitoring threads"""
        # System health monitoring
        health_thread = threading.Thread(target=self.monitor_system_health, daemon=True)
        health_thread.start()
        
        # Security monitoring
        security_thread = threading.Thread(target=self.monitor_security_events, daemon=True)
        security_thread.start()
        
        # Performance monitoring
        perf_thread = threading.Thread(target=self.monitor_performance, daemon=True)
        perf_thread.start()
        
        logging.info("Monitoring threads started")
    
    def monitor_system_health(self):
        """Monitor system health continuously"""
        while True:
            try:
                # Check server health
                start_time = time.time()
                try:
                    response = requests.get(f"{self.server_url}/health", timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        self.system_metrics['server_status'] = 'online'
                        self.system_metrics['active_sessions'] = data.get('active_sessions', 0)
                        self.system_metrics['total_users'] = data.get('total_users', 0)
                    else:
                        self.system_metrics['server_status'] = 'error'
                except:
                    self.system_metrics['server_status'] = 'offline'
                
                response_time = (time.time() - start_time) * 1000
                
                # Check card simulator
                try:
                    card_response = requests.get(f"{self.card_url}/", timeout=3)
                    self.system_metrics['card_status'] = 'online' if card_response.status_code == 200 else 'error'
                except:
                    self.system_metrics['card_status'] = 'offline'
                
                # Emit real-time updates
                socketio.emit('system_metrics', {
                    'timestamp': datetime.now().isoformat(),
                    'metrics': self.system_metrics,
                    'response_time': response_time
                })
                
                # Log to database
                self.log_system_metric('health_check', 'success', {
                    'server_status': self.system_metrics['server_status'],
                    'card_status': self.system_metrics['card_status'],
                    'response_time': response_time
                })
                
                time.sleep(10)  # Check every 10 seconds
                
            except Exception as e:
                logging.error(f"Health monitoring error: {e}")
                time.sleep(30)
    
    def monitor_security_events(self):
        """Monitor for security events and anomalies"""
        while True:
            try:
                # Check for security status
                response = requests.get(f"{self.server_url}/admin/security/status", timeout=5)
                if response.status_code == 200:
                    security_data = response.json()
                    
                    # Check for locked users
                    locked_users = security_data.get('locked_users', {})
                    if locked_users:
                        for user_id, lockout_time in locked_users.items():
                            self.create_alert('security', 'warning', 
                                            f'User {user_id} is locked until {lockout_time}')
                    
                    # Check failed attempts
                    failed_attempts = security_data.get('failed_attempts', {})
                    total_failed = sum(failed_attempts.values())
                    
                    if total_failed > self.alert_thresholds['concurrent_failures']:
                        self.create_alert('security', 'critical',
                                        f'High number of failed attempts: {total_failed}')
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logging.error(f"Security monitoring error: {e}")
                time.sleep(60)
    
    def monitor_performance(self):
        """Monitor system performance metrics"""
        while True:
            try:
                # Test response times
                endpoints = [
                    f"{self.server_url}/health",
                    f"{self.server_url}/admin/users",
                    f"{self.server_url}/admin/sessions"
                ]
                
                for endpoint in endpoints:
                    start_time = time.time()
                    try:
                        response = requests.get(endpoint, timeout=10)
                        response_time = (time.time() - start_time) * 1000
                        
                        if response_time > self.alert_thresholds['response_time_ms']:
                            self.create_alert('performance', 'warning',
                                            f'Slow response from {endpoint}: {response_time:.2f}ms')
                        
                        # Emit performance data
                        socketio.emit('performance_data', {
                            'endpoint': endpoint,
                            'response_time': response_time,
                            'status_code': response.status_code,
                            'timestamp': datetime.now().isoformat()
                        })
                        
                    except Exception as e:
                        self.create_alert('performance', 'error',
                                        f'Failed to reach {endpoint}: {str(e)}')
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logging.error(f"Performance monitoring error: {e}")
                time.sleep(120)
    
    def log_access_attempt(self, log_data):
        """Log access attempt to database and update stats"""
        try:
            # Add to in-memory logs
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'reader_id': log_data.get('reader_id', 'unknown'),
                'user_id': log_data.get('user_id', 'unknown'),
                'user_name': log_data.get('user_name', 'Unknown'),
                'decision': log_data.get('decision', 'UNKNOWN'),
                'reason': log_data.get('reason', ''),
                'access_zone': log_data.get('access_zone', 'UNKNOWN'),
                'response_time': log_data.get('response_time', 0),
                'biometric_used': log_data.get('biometric_used', False),
                'ip_address': log_data.get('ip_address', 'unknown')
            }
            
            self.access_logs.append(log_entry)
            
            # Update statistics
            self.stats['total_attempts'] += 1
            if log_entry['decision'] == 'ALLOW':
                self.stats['successful_attempts'] += 1
            else:
                self.stats['failed_attempts'] += 1
            
            self.stats['unique_users'].add(log_entry['user_id'])
            self.stats['popular_zones'][log_entry['access_zone']] += 1
            
            current_hour = datetime.now().strftime('%Y-%m-%d %H:00')
            current_day = datetime.now().strftime('%Y-%m-%d')
            self.stats['hourly_stats'][current_hour] += 1
            self.stats['daily_stats'][current_day] += 1
            
            # Save to database
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO access_logs 
                    (reader_id, user_id, user_name, decision, reason, access_zone, 
                     response_time, biometric_used, ip_address)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    log_entry['reader_id'], log_entry['user_id'], log_entry['user_name'],
                    log_entry['decision'], log_entry['reason'], log_entry['access_zone'],
                    log_entry['response_time'], log_entry['biometric_used'], log_entry['ip_address']
                ))
                conn.commit()
            
            # Emit real-time update
            socketio.emit('access_log', log_entry)
            
            # Check for alerts
            self.check_access_alerts(log_entry)
            
        except Exception as e:
            logging.error(f"Error logging access attempt: {e}")
    
    def check_access_alerts(self, log_entry):
        """Check if access attempt triggers any alerts"""
        # Check for repeated failed attempts
        if log_entry['decision'] == 'DENY':
            recent_fails = [log for log in list(self.access_logs)[-10:] 
                          if log['user_id'] == log_entry['user_id'] and log['decision'] == 'DENY']
            
            if len(recent_fails) >= 3:
                self.create_alert('security', 'warning',
                                f"Multiple failed attempts by user {log_entry['user_id']}")
        
        # Check for unusual access patterns
        if log_entry['access_zone'] in ['SERVER_ROOM', 'MANAGEMENT_FLOOR']:
            if log_entry['decision'] == 'ALLOW':
                self.create_alert('access', 'info',
                                f"High-security zone access: {log_entry['user_name']} → {log_entry['access_zone']}")
    
    def create_alert(self, alert_type, severity, message):
        """Create and emit alert"""
        alert = {
            'id': len(self.alerts) + 1,
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'message': message,
            'acknowledged': False
        }
        
        self.alerts.append(alert)
        
        # Log to database
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO security_events (event_type, severity, description)
                VALUES (?, ?, ?)
            ''', (alert_type, severity, message))
            conn.commit()
        
        # Emit real-time alert
        socketio.emit('alert', alert)
        
        logging.info(f"Alert created: {severity} - {message}")
    
    def log_system_metric(self, metric_name, metric_value, details=None):
        """Log system metric to database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO system_metrics (metric_name, metric_value, details)
                    VALUES (?, ?, ?)
                ''', (metric_name, str(metric_value), json.dumps(details) if details else None))
                conn.commit()
        except Exception as e:
            logging.error(f"Error logging system metric: {e}")
    
    def get_dashboard_data(self):
        """Get comprehensive dashboard data"""
        # Convert set to list for JSON serialization
        stats_copy = self.stats.copy()
        stats_copy['unique_users'] = len(stats_copy['unique_users'])
        
        return {
            'system_metrics': self.system_metrics,
            'statistics': stats_copy,
            'recent_logs': list(self.access_logs)[-50:],  # Last 50 logs
            'recent_alerts': list(self.alerts)[-20:],  # Last 20 alerts
            'popular_zones': dict(self.stats['popular_zones']),
            'hourly_activity': dict(list(self.stats['hourly_stats'].items())[-24:])  # Last 24 hours
        }

# Global monitor instance
monitor = AccessControlMonitor()

# ================== WEB ROUTES ==================

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/dashboard')
def api_dashboard():
    """API endpoint for dashboard data"""
    return jsonify(monitor.get_dashboard_data())

@app.route('/api/logs')
def api_logs():
    """Get access logs with pagination"""
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 50))
    
    # Get logs from database
    with sqlite3.connect(monitor.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('''
            SELECT * FROM access_logs 
            ORDER BY timestamp DESC 
            LIMIT ? OFFSET ?
        ''', (per_page, (page - 1) * per_page))
        
        logs = cursor.fetchall()
        
        # Get total count
        cursor.execute('SELECT COUNT(*) FROM access_logs')
        total = cursor.fetchone()[0]
    
    return jsonify({
        'logs': logs,
        'total': total,
        'page': page,
        'per_page': per_page
    })

@app.route('/api/alerts')
def api_alerts():
    """Get alerts"""
    return jsonify(list(monitor.alerts))

@app.route('/api/alerts/<int:alert_id>/acknowledge', methods=['POST'])
def acknowledge_alert(alert_id):
    """Acknowledge an alert"""
    for alert in monitor.alerts:
        if alert['id'] == alert_id:
            alert['acknowledged'] = True
            socketio.emit('alert_acknowledged', alert)
            return jsonify({'status': 'success'})
    
    return jsonify({'status': 'not_found'}), 404

@app.route('/api/simulate_access', methods=['POST'])
def simulate_access():
    """Simulate access attempt for testing"""
    data = request.get_json()
    
    # Create fake log entry
    log_data = {
        'reader_id': 'test_reader',
        'user_id': data.get('user_id', 'test_user'),
        'user_name': data.get('user_name', 'Test User'),
        'decision': data.get('decision', 'ALLOW'),
        'reason': data.get('reason', 'Test simulation'),
        'access_zone': data.get('access_zone', 'MAIN_ENTRANCE'),
        'response_time': data.get('response_time', 150),
        'biometric_used': data.get('biometric_used', False),
        'ip_address': request.remote_addr
    }
    
    monitor.log_access_attempt(log_data)
    
    return jsonify({'status': 'success', 'log_data': log_data})

@app.route('/api/export/logs')
def export_logs():
    """Export logs as JSON"""
    with sqlite3.connect(monitor.db_path) as conn:
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT 1000')
        logs = cursor.fetchall()
    
    return jsonify(logs)

# ================== WEBSOCKET EVENTS ==================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'data': 'Connected to Access Control Monitor'})
    
    # Send initial dashboard data
    emit('dashboard_data', monitor.get_dashboard_data())

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    print('Client disconnected')

@socketio.on('request_dashboard_update')
def handle_dashboard_update():
    """Handle request for dashboard update"""
    emit('dashboard_data', monitor.get_dashboard_data())

if __name__ == '__main__':
    print("=" * 60)
    print("🖥️  ACCESS CONTROL MONITOR SERVER")
    print("=" * 60)
    print(f"🌐 Monitor Dashboard: http://localhost:6000")
    print(f"📊 API Endpoints:")
    print(f"   GET  /api/dashboard - Dashboard data")
    print(f"   GET  /api/logs - Access logs")
    print(f"   GET  /api/alerts - System alerts")
    print(f"   POST /api/simulate_access - Simulate access")
    print("=" * 60)
    print("📡 Real-time monitoring active...")
    print("🔍 Monitoring system health every 10 seconds")
    print("🛡️  Monitoring security events every 30 seconds")
    print("⚡ Monitoring performance every 60 seconds")
    print("=" * 60)
    
    # Create templates directory if it doesn't exist
    os.makedirs('templates', exist_ok=True)
    
    socketio.run(app, host='0.0.0.0', port=6000, debug=False)