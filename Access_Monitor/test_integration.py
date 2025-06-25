import requests
import json
import time
import random

def test_monitor_integration():
    """Test Monitor integration with Access Control System"""
    monitor_url = "http://localhost:6000"
    
    print("🧪 Testing Monitor Integration")
    print("=" * 50)
    
    # Test 1: Monitor Health
    print("1. Testing Monitor Health...")
    try:
        response = requests.get(f"{monitor_url}/api/dashboard")
        if response.status_code == 200:
            print("   ✅ Monitor API is working")
            data = response.json()
            print(f"   📊 Dashboard data keys: {list(data.keys())}")
        else:
            print(f"   ❌ Monitor API error: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Monitor not accessible: {e}")
    
    # Test 2: Simulate Access Attempts
    print("\n2. Simulating Access Attempts...")
    test_scenarios = [
        {
            "user_id": "user001",
            "user_name": "John Doe",
            "decision": "ALLOW",
            "access_zone": "MAIN_ENTRANCE",
            "reason": "Valid access"
        },
        {
            "user_id": "user002", 
            "user_name": "Jane Smith",
            "decision": "ALLOW",
            "access_zone": "MANAGEMENT_FLOOR",
            "reason": "Biometric verified",
            "biometric_used": True
        },
        {
            "user_id": "user003",
            "user_name": "Bob Wilson", 
            "decision": "DENY",
            "access_zone": "SERVER_ROOM",
            "reason": "Insufficient access level"
        },
        {
            "user_id": "user004",
            "user_name": "Alice Brown",
            "decision": "DENY", 
            "access_zone": "MAIN_ENTRANCE",
            "reason": "User status: suspended"
        },
        {
            "user_id": "attacker001",
            "user_name": "Evil Hacker",
            "decision": "DENY",
            "access_zone": "SERVER_ROOM", 
            "reason": "Multiple security violations"
        }
    ]
    
    for i, scenario in enumerate(test_scenarios):
        try:
            scenario["response_time"] = random.randint(100, 500)
            
            response = requests.post(f"{monitor_url}/api/simulate_access", json=scenario)
            if response.status_code == 200:
                print(f"   ✅ Scenario {i+1}: {scenario['user_name']} → {scenario['decision']}")
            else:
                print(f"   ❌ Scenario {i+1} failed: {response.status_code}")
                
            time.sleep(1)  # Space out requests
            
        except Exception as e:
            print(f"   ❌ Scenario {i+1} error: {e}")
    
    # Test 3: Check Dashboard Update
    print("\n3. Checking Dashboard Update...")
    try:
        response = requests.get(f"{monitor_url}/api/dashboard")
        if response.status_code == 200:
            data = response.json()
            stats = data.get('statistics', {})
            print(f"   📊 Total attempts: {stats.get('total_attempts', 0)}")
            print(f"   ✅ Successful: {stats.get('successful_attempts', 0)}")
            print(f"   ❌ Failed: {stats.get('failed_attempts', 0)}")
            print(f"   👥 Unique users: {stats.get('unique_users', 0)}")
            
            zones = data.get('popular_zones', {})
            if zones:
                print(f"   🏢 Popular zones: {', '.join(zones.keys())}")
                
        else:
            print(f"   ❌ Dashboard update check failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Dashboard check error: {e}")
    
    # Test 4: Export Data
    print("\n4. Testing Data Export...")
    try:
        response = requests.get(f"{monitor_url}/api/export/logs")
        if response.status_code == 200:
            logs = response.json()
            print(f"   ✅ Exported {len(logs)} log entries")
        else:
            print(f"   ❌ Export failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Export error: {e}")
    
    print(f"\n🎯 Monitor Integration Test Complete!")
    print(f"🌐 Open http://localhost:6000 to view the dashboard")

if __name__ == "__main__":
    test_monitor_integration()