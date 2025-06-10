import subprocess
import time
import os
import signal
import sys
from threading import Thread

class DilithiumServiceManager:
    def __init__(self):
        self.processes = []
        self.running = True
        
        # Detect the correct Python executable for virtual environment
        self.venv_python = self.find_venv_python()
        
    def find_venv_python(self):
        """Find the correct Python executable for virtual environment"""
        # Check for venv directory
        venv_paths = [
            "venv/bin/python3",
            "venv/bin/python",
            "./venv/bin/python3",
            "./venv/bin/python"
        ]
        
        for path in venv_paths:
            if os.path.exists(path):
                print(f"✅ Found virtual environment Python: {path}")
                return path
        
        print("⚠️ Virtual environment not found, using system Python")
        return sys.executable
        
    def start_mqtt_broker(self):
        """Start MQTT broker (mosquitto)"""
        try:
            print("🦟 Starting MQTT broker...")
            # Check if mosquitto is already running
            try:
                result = subprocess.run(["pgrep", "mosquitto"], capture_output=True)
                if result.returncode == 0:
                    print("✅ MQTT broker already running")
                    return True
            except:
                pass
            
            # Try to start mosquitto
            process = subprocess.Popen(
                ["mosquitto", "-v"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.processes.append(process)
            print("✅ MQTT broker started")
            return True
        except FileNotFoundError:
            print("⚠️ Mosquitto not found. Install with: sudo apt install mosquitto mosquitto-clients")
            return False
    
    def start_backend_server(self):
        """Start backend server with correct virtual environment"""
        print("🖥️ Starting backend server...")
        print(f"   Using Python: {self.venv_python}")
        
        # Use sudo with virtual environment Python
        if self.venv_python.startswith("venv/"):
            cmd = ["sudo", self.venv_python, "02_backend_server.py"]
        else:
            cmd = [self.venv_python, "02_backend_server.py"]
            
        process = subprocess.Popen(cmd)
        self.processes.append(process)
        print("✅ Backend server started")
    
    def start_web_dashboard(self):
        """Start web dashboard with correct virtual environment"""
        print("🌐 Starting web dashboard...")
        print(f"   Using Python: {self.venv_python}")
        
        # Use virtual environment Python for web dashboard too
        process = subprocess.Popen([
            self.venv_python, "Web.py" 
        ])
        self.processes.append(process)
        print("✅ Web dashboard started")
    
    def check_dependencies(self):
        """Check if all dependencies are available"""
        print("🔍 Checking dependencies...")
        
        # Check virtual environment
        if not os.path.exists("venv"):
            print("❌ Virtual environment not found!")
            print("   Create with: python3 -m venv venv")
            print("   Activate with: source venv/bin/activate")
            print("   Install deps: pip install paho-mqtt liboqs-python flask")
            return False
        
        # Check OQS library
        try:
            result = subprocess.run([
                self.venv_python, "-c", 
                "from oqs import Signature; print('OQS OK')"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ OQS library available")
            else:
                print("❌ OQS library not available")
                print("   Install with: sudo venv/bin/pip install liboqs-python")
                return False
        except:
            print("❌ Failed to check OQS library")
            return False
        
        # Check config files
        config_files = [
            "config/system_params.json",
            "config/server_keys.json"
        ]
        
        for config_file in config_files:
            if not os.path.exists(config_file):
                print(f"❌ Missing config file: {config_file}")
                print("   Run setup first: python3 01_system_setup.py")
                return False
        
        print("✅ All dependencies check passed")
        return True
    
    def stop_all_services(self):
        """Stop all services"""
        print("\n🛑 Stopping all services...")
        self.running = False
        
        for process in self.processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            except:
                pass
        
        print("✅ All services stopped")
    
    def run(self):
        """Run all services"""
        print("🚀 === Dilithium RFID System Startup ===")
        print()
        
        # Check dependencies first
        if not self.check_dependencies():
            print("❌ Dependency check failed. Please fix the issues above.")
            return
        
        # Start MQTT broker
        if not self.start_mqtt_broker():
            print("❌ Failed to start MQTT broker")
            return
        
        time.sleep(2)
        
        # Start backend server
        try:
            self.start_backend_server()
            time.sleep(3)
        except Exception as e:
            print(f"❌ Failed to start backend server: {e}")
            return
        
        # Start web dashboard
        try:
            self.start_web_dashboard()
            time.sleep(2)
        except Exception as e:
            print(f"❌ Failed to start web dashboard: {e}")
            return
        
        print()
        print("🎯 === System Ready ===")
        print("📊 Web Dashboard: http://localhost:5000")
        print("📡 MQTT Broker: localhost:1883")
        print("🔒 Backend Server: Running with Dilithium mutual auth")
        print()
        print("🏷️ Now you can:")
        print("   1. Flash ESP32 with the provided code")
        print("   2. Provision cards using: python3 03_card_provisioning.py")
        print("   3. Watch authentication in real-time on web dashboard")
        print("   4. Test security attacks from the dashboard")
        print()
        print("Press Ctrl+C to stop all services")
        
        # Handle shutdown
        def signal_handler(sig, frame):
            self.stop_all_services()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Keep running and monitor processes
        try:
            while self.running:
                # Check if any process has died
                for i, process in enumerate(self.processes):
                    if process.poll() is not None:
                        print(f"⚠️ Process {i} has stopped (exit code: {process.returncode})")
                
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_all_services()

if __name__ == "__main__":
    # Change to script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)
    
    manager = DilithiumServiceManager()
    manager.run()