# 🔥 ATTACK SIMULATION & TESTING GUIDE
## Federated NIDS - Live Attack Data Troubleshooting & Testing

---

## 📋 DIAGNOSIS: Why No Attack Data Appears

Based on your code analysis, here's why attack data might not be visible on the dashboard:

### **Issue 1: Insufficient Network Traffic** ⚠️
**Problem:** Your client needs **real network traffic** to analyze
- The client is capturing packets but there may not be enough traffic
- Minimum **15 packets** required before ML classification kicks in
- Classification happens every **10 packets** after that

**Evidence in code:**
```python
MIN_PACKETS_FOR_CLASSIFICATION = 15  # client.py line in config
CLASSIFICATION_INTERVAL = 10
```

### **Issue 2: No Attack-Like Traffic** ⚠️
**Problem:** Normal browsing doesn't trigger attack detection
- Your ML model looks for specific attack patterns
- Normal web browsing = classified as "Normal" (label 2)
- Only labels {0, 1, 4} trigger alerts (BruteForce, DoS/DDoS, PortScan)

**Evidence in code:**
```python
ATTACK_LABELS = {0, 1, 4}  # Only these trigger alerts
if pred in config.ATTACK_LABELS and conf >= config.CONFIDENCE_THRESHOLD:
    # Alert triggered
```

### **Issue 3: High Confidence Threshold** ⚠️
**Problem:** Attacks need 75% confidence to trigger
```python
CONFIDENCE_THRESHOLD = 0.75  # 75% confidence required
```

### **Issue 4: Firewall Blocking Packets** ⚠️
**Problem:** If firewall rules exist from previous runs, legitimate test traffic might be blocked
```python
# Packets from blocked IPs are dropped immediately
if src_ip in blocked_ips:
    stats['packets_dropped'] += 1
    return
```

---

## 🔍 STEP-BY-STEP DIAGNOSIS

### **Step 1: Check if Client is Actually Processing Packets**

Run this in a separate terminal while client is running:

```bash
# On Windows PowerShell
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "NIDS_Block*"}
```

Check client console output - you should see:
```
📊 STATUS - HH:MM:SS
   Captured: XXX | Processed: YYY | Dropped: ZZZ
   Flows: N | Attacks: 0 | ...
```

**If Captured = 0:** Network capture isn't working (need admin rights)
**If Processed = 0:** All packets are being filtered or blocked
**If Attacks = 0:** No attack patterns detected (normal!)

### **Step 2: Check Server Console**

Look for these in server console:
```
✅ CLIENT SUCCESSFULLY REGISTERED!
   Total clients now: 1
   Active clients: ['laptop_2']
```

**If missing:** Registration failed - check socket.io connection

### **Step 3: Check Dashboard API Endpoints**

Open browser and visit:
- `http://localhost:5000/api/status` - Should show server stats
- `http://localhost:5000/api/clients` - Should show connected clients
- `http://localhost:5000/api/attacks/recent` - Should show attack list (empty is OK)

---

## 🎯 SOLUTION 1: Generate Simulated Attack Traffic (SAFE & ETHICAL)

### **Method A: Local Port Scan Simulation** (Safest)

Create this Python script to simulate port scanning:

```python
# test_portscan.py
import socket
import time

target = "127.0.0.1"  # Scan yourself (safe!)
ports = range(1, 1000)  # Scan first 1000 ports

print(f"🔍 Simulating port scan on {target}...")
print(f"   This will trigger PortScan detection\n")

for port in ports:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.1)
        sock.connect((target, port))
        sock.close()
    except:
        pass
    
    if port % 100 == 0:
        print(f"   Scanned {port} ports...")
        time.sleep(0.5)  # Slight pause

print("\n✅ Port scan simulation complete!")
print("   Check NIDS dashboard for PortScan detection")
```

**Run it:**
```bash
python test_portscan.py
```

This should trigger:
- High packet rate
- Multiple connections to different ports
- PortScan classification by ML model

### **Method B: SYN Flood Simulation** (Requires Scapy)

```python
# test_synflood.py - RUN AS ADMINISTRATOR
from scapy.all import IP, TCP, send
import random

target_ip = "127.0.0.1"  # Attack yourself (safe!)
target_port = 80

print(f"🌊 Simulating SYN flood to {target_ip}:{target_port}")
print(f"   This will trigger DoS/DDoS detection\n")

for i in range(500):  # Send 500 SYN packets
    src_port = random.randint(1024, 65535)
    
    packet = IP(dst=target_ip) / TCP(
        sport=src_port,
        dport=target_port,
        flags='S'  # SYN flag
    )
    
    send(packet, verbose=False)
    
    if i % 100 == 0:
        print(f"   Sent {i} SYN packets...")

print("\n✅ SYN flood simulation complete!")
print("   Check NIDS dashboard for DoS/DDoS detection")
```

**Run it:**
```bash
# Run as Administrator!
python test_synflood.py
```

### **Method C: High Traffic Generator** (Simple)

```python
# test_traffic.py
import socket
import threading
import time

def generate_connections(target, port, count):
    """Generate many rapid connections"""
    for i in range(count):
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((target, port))
            sock.send(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
            sock.close()
        except:
            pass

target = "127.0.0.1"
port = 80

print(f"📊 Generating high traffic to {target}:{port}")
print(f"   This will trigger rate-based detection\n")

# Start multiple threads to generate traffic burst
threads = []
for i in range(10):  # 10 parallel threads
    t = threading.Thread(target=generate_connections, args=(target, port, 100))
    t.start()
    threads.append(t)

for t in threads:
    t.join()

print("\n✅ Traffic generation complete!")
print("   Check NIDS for rate-based attack detection")
```

---

## 🎯 SOLUTION 2: Use Real Attack Testing Tools

### **Option 1: Nmap (Port Scanner)**

```bash
# Install from https://nmap.org/download.html

# Safe local scan
nmap -sS -p 1-10000 127.0.0.1

# Aggressive scan (more detectable)
nmap -A -T4 127.0.0.1
```

### **Option 2: hping3 (Traffic Generator)**

```bash
# Install from https://www.hping.org/

# SYN flood
hping3 -S -p 80 --flood 127.0.0.1

# UDP flood
hping3 --udp -p 80 --flood 127.0.0.1
```

### **Option 3: Metasploit (Advanced)**

⚠️ **ONLY for testing on your OWN systems**

```bash
# Use auxiliary scanners
msfconsole
> use auxiliary/scanner/portscan/tcp
> set RHOSTS 127.0.0.1
> set PORTS 1-1000
> run
```

---

## 🎯 SOLUTION 3: Lower Detection Thresholds (For Testing)

Edit `config.py` to make detection more sensitive:

```python
# ORIGINAL (production values)
CONFIDENCE_THRESHOLD = 0.75
THREAT_SCORE_LIMIT = 2
MIN_PACKETS_FOR_CLASSIFICATION = 15

# TESTING (more sensitive)
CONFIDENCE_THRESHOLD = 0.50  # 50% confidence
THREAT_SCORE_LIMIT = 1       # Block after 1 detection
MIN_PACKETS_FOR_CLASSIFICATION = 5  # Classify faster
```

**After changing:**
1. Stop client (Ctrl+C)
2. Restart client: `START_CLIENT.bat`
3. Generate some traffic (browse websites, download files)
4. Watch for more detections

⚠️ **Remember to restore original values after testing!**

---

## 🎯 SOLUTION 4: Enable Verbose Debug Logging

Edit `config.py`:

```python
VERBOSE = True
DEBUG_MODE = True  # Enable this!
```

This will show:
- Every packet classification attempt
- Feature extraction details
- Why packets are/aren't classified as attacks

---

## 🎯 SOLUTION 5: Manual Attack Data Injection (For Dashboard Testing)

If you just want to test if the **dashboard works**, create this script:

```python
# test_dashboard_inject.py
import socketio
import time

sio = socketio.Client()

@sio.event
def connect():
    print("✅ Connected to server")
    
    # Register fake client
    sio.emit('register_client', {
        'client_id': 'test_client',
        'client_ip': '192.168.1.100'
    })
    
    time.sleep(2)
    
    # Inject fake attacks
    for i in range(10):
        sio.emit('attack_detected', {
            'client_id': 'test_client',
            'ip_address': f'10.0.0.{i+1}',
            'attack_type': ['BruteForce', 'DoS/DDoS', 'PortScan'][i % 3],
            'confidence': 0.85 + (i * 0.01),
            'threat_score': (i % 3) + 1
        })
        print(f"📤 Sent fake attack {i+1}")
        time.sleep(1)
    
    # Block some IPs
    sio.emit('block_ip', {
        'client_id': 'test_client',
        'ip_address': '10.0.0.1',
        'reason': 'Test block'
    })
    
    print("\n✅ Test data injection complete!")
    print("   Check dashboard at http://localhost:5000")

sio.connect('http://localhost:5000')
time.sleep(15)
sio.disconnect()
```

**Run it:**
```bash
python test_dashboard_inject.py
```

This will populate the dashboard with test data to verify frontend works.

---

## 📊 EXPECTED RESULTS

### **When Attack is Detected:**

**Client Console:**
```
🚨 ML ATTACK DETECTED!
   Type: PortScan
   Source: 192.168.1.50:12345
   Confidence: 85.2%
   Packets: 25
   Threat Score: 1/2

🚫 BLOCKING IP: 192.168.1.50
   Reason: PortScan
   ✅ Firewall rules created
   ✅ Saved to JSON file
   ✅ Synced to server
```

**Server Console:**
```
🚨 ATTACK DETECTED!
   Type: PortScan from 192.168.1.50 (85.2%)
   Client: laptop_2

🚫 BLOCK REQUEST from laptop_2: 192.168.1.50 (PortScan)
   📊 Successfully sent to 1/1 clients
```

**Dashboard:**
- Attack counter increases
- New entry in "Recent Attacks" table
- Chart updates with new data point
- Blocked IPs list shows new IP

---

## 🚨 TROUBLESHOOTING CHECKLIST

- [ ] Client shows "Captured" packets > 0
- [ ] Server console shows client registration
- [ ] `/api/clients` shows your client
- [ ] Firewall rules exist: `Get-NetFirewallRule | Where DisplayName -like "NIDS*"`
- [ ] Client running as **Administrator**
- [ ] No antivirus blocking packet capture
- [ ] Config threshold not too high (try 0.5 for testing)
- [ ] Generated traffic actually reaching your machine
- [ ] Dashboard WebSocket connected (check browser console)

---

## ⚖️ ETHICAL & LEGAL CONSIDERATIONS

### ✅ **SAFE & LEGAL:**
- Testing on **127.0.0.1** (localhost)
- Testing on **your own devices** on **your own network**
- Port scanning **yourself**
- Traffic generation to **your own services**
- Using the provided Python test scripts

### ⛔ **ILLEGAL & UNETHICAL:**
- Scanning **external IPs** without permission
- Attacking **any system you don't own**
- Testing on **corporate/school networks** without authorization
- DoS attacks on **public services**
- Using tools on **someone else's network**

### 📜 **Best Practices:**
1. Only test on **isolated lab environment**
2. Disconnect from internet during testing
3. Notify anyone sharing your network
4. Use **virtual machines** for realistic testing
5. Document all testing activities
6. Restore normal configurations after testing

---

## 🎓 RECOMMENDED TESTING SETUP

### **Ideal Testing Environment:**

```
┌─────────────────────────────────────┐
│  Your Computer (Host)               │
│  ├── VirtualBox/VMware              │
│  │   ├── VM1: Server + Dashboard    │
│  │   └── VM2: Client (Attacker)     │
│  │                                   │
│  └── Network: Host-Only Adapter     │
│      (Isolated network)              │
└─────────────────────────────────────┘
```

**Benefits:**
- Completely isolated from real network
- Can generate aggressive traffic safely
- Can test blocking without affecting real connectivity
- Multiple clients easy to set up

---

## 📝 QUICK START: 5-Minute Test

1. **Lower threshold** (edit `config.py`):
   ```python
   CONFIDENCE_THRESHOLD = 0.5
   MIN_PACKETS_FOR_CLASSIFICATION = 5
   ```

2. **Restart client**

3. **Run simple test**:
   ```bash
   python test_portscan.py
   ```

4. **Check dashboard**: http://localhost:5000

5. **Restore config** after testing

---

## 🆘 Still No Attacks Showing?

### **Run This Diagnostic Script:**

```python
# diagnose.py
import requests
import json

print("=== NIDS DIAGNOSTIC ===\n")

# Check server
try:
    r = requests.get('http://localhost:5000/api/status')
    data = r.json()
    print(f"✅ Server Status: {data['status']}")
    print(f"   Clients Connected: {data['clients_connected']}")
    print(f"   Total Attacks: {data['global_stats']['total_attacks_detected']}")
except Exception as e:
    print(f"❌ Server Error: {e}")

# Check clients
try:
    r = requests.get('http://localhost:5000/api/clients')
    data = r.json()
    print(f"\n✅ Clients: {data['count']}")
    for cid, cdata in data['clients'].items():
        print(f"   {cid}: {cdata['status']}")
except Exception as e:
    print(f"❌ Client Check Error: {e}")

# Check attacks
try:
    r = requests.get('http://localhost:5000/api/attacks/recent')
    data = r.json()
    print(f"\n📊 Recent Attacks: {data['count']}")
    for attack in data['attacks'][:5]:
        print(f"   {attack['timestamp']}: {attack['attack_type']} from {attack['ip_address']}")
except Exception as e:
    print(f"❌ Attack Check Error: {e}")
```

**Run it:**
```bash
python diagnose.py
```

This will show you exactly what data the server has.

---

## 📞 Need More Help?

Check these files in your project:
- `federated/nids.log` - Detailed event log
- `federated/blocked_ips.json` - Currently blocked IPs
- Client console output - Real-time packet stats
- Browser console (F12) - WebSocket errors

**Common fixes:**
1. Restart both server and client
2. Clear `blocked_ips.json`
3. Remove all firewall rules: `netsh advfirewall firewall delete rule name="NIDS_Block_*"`
4. Check Windows Firewall isn't blocking Python
5. Try running test scripts as Administrator
