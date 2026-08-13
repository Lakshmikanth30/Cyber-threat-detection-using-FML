# 🧪 NIDS Testing Suite

This folder contains tools to test, diagnose, and simulate attacks for your Federated NIDS project.

---

## 📁 Files Overview

| File | Purpose |
|------|---------|
| `diagnose.py` | **Diagnostic tool** - Check system status and identify issues |
| `test_portscan.py` | **Port scan simulator** - Generate PortScan attacks |
| `test_traffic_flood.py` | **Traffic flood simulator** - Generate DoS/DDoS attacks |
| `test_dashboard_inject.py` | **Dashboard tester** - Inject fake data to test UI |
| `ATTACK_SIMULATION_GUIDE.md` | **Complete guide** - Detailed explanations and solutions |

---

## 🚀 Quick Start

### **Step 1: Diagnose Current Status**

```bash
python testing/diagnose.py
```

This will show:
- ✅ Server status
- ✅ Connected clients
- ✅ Recent attacks
- ✅ Configuration issues

### **Step 2: Generate Test Attacks**

Choose one:

**Option A: Port Scan (Easiest)**
```bash
python testing/test_portscan.py
```

**Option B: Traffic Flood**
```bash
python testing/test_traffic_flood.py
```

**Option C: Dashboard Test (No ML)**
```bash
python testing/test_dashboard_inject.py
```

### **Step 3: Check Dashboard**

Open: http://localhost:5000

You should see:
- Attack counter increased
- Recent attacks listed
- Charts updated
- Blocked IPs shown

---

## 🔍 Troubleshooting

### Problem: "No attacks appearing on dashboard"

**Diagnosis:**
```bash
python testing/diagnose.py
```

**Common Causes:**

1. **Client not capturing packets**
   - Make sure client runs as Administrator
   - Check client console shows "Captured: XXX"

2. **No attack-like traffic**
   - Normal browsing = classified as Normal
   - Run `test_portscan.py` to generate attacks

3. **Threshold too high**
   - Edit `federated/config.py`
   - Set `CONFIDENCE_THRESHOLD = 0.5` (for testing)
   - Restart client

4. **Client not connected**
   - Check server console for registration
   - Visit http://localhost:5000/api/clients
   - Should show your client

---

## ⚙️ Testing Configuration

For **easier detection during testing**, edit `federated/config.py`:

```python
# TESTING VALUES (more sensitive)
CONFIDENCE_THRESHOLD = 0.5          # Lower from 0.75
MIN_PACKETS_FOR_CLASSIFICATION = 5  # Lower from 15
THREAT_SCORE_LIMIT = 1              # Lower from 2
```

⚠️ **Remember to restore production values after testing!**

---

## 🎯 Test Scenarios

### Scenario 1: Quick Dashboard Test
**Goal:** Verify dashboard UI works

```bash
python testing/test_dashboard_inject.py
# Select option 1 (Normal mode)
```

**Expected:** Dashboard shows 20 fake attacks immediately

---

### Scenario 2: Real ML Detection Test
**Goal:** Test actual ML model detection

```bash
# 1. Make sure client is running
# 2. Run port scanner
python testing/test_portscan.py
# Select option 2 (Medium - 500 ports)
```

**Expected:**
- Client console shows "PortScan detected"
- Dashboard updates with real detection
- 127.0.0.1 might get blocked

---

### Scenario 3: Rate-Based Detection
**Goal:** Trigger high traffic detection

```bash
python testing/test_traffic_flood.py
# Select option 2 (TCP Medium)
```

**Expected:**
- Client detects high packet rate
- Classified as "DoS/DDoS" or "Flood Attack"
- IP gets blocked after threshold

---

### Scenario 4: Full System Test
**Goal:** Test everything together

```bash
# Terminal 1: Run diagnostics
python testing/diagnose.py

# Terminal 2: Generate varied attacks
python testing/test_portscan.py      # PortScan
python testing/test_traffic_flood.py # DoS

# Terminal 3: Watch server logs
# (Just keep server console visible)
```

---

## 📊 Understanding Results

### Client Console Output

**Normal Operation:**
```
📊 STATUS - 14:30:15
   Captured: 1523 | Processed: 1500 | Dropped: 23
   Flows: 45 | Attacks: 3 | ...
```

**Attack Detected:**
```
🚨 ML ATTACK DETECTED!
   Type: PortScan
   Source: 192.168.1.50:12345
   Confidence: 85.2%
   Packets: 25
   Threat Score: 1/2
```

**IP Blocked:**
```
🚫 BLOCKING IP: 192.168.1.50
   Reason: PortScan
   ✅ Firewall rules created
   ✅ Saved to JSON file
   ✅ Synced to server
```

### Server Console Output

```
🚨 ATTACK DETECTED!
   Type: PortScan from 192.168.1.50 (85.2%)
   Client: laptop_2

🚫 BLOCK REQUEST from laptop_2: 192.168.1.50 (PortScan)
   📊 Successfully sent to 1/1 clients
```

### Dashboard Display

- **Stats Cards:** Show total attacks, blocked IPs, etc.
- **Recent Attacks Table:** Lists attack type, IP, confidence
- **Timeline Chart:** Visual graph of attacks over time
- **Blocked IPs List:** All currently blocked IPs

---

## ⚖️ Safety & Ethics

### ✅ SAFE Testing Practices:

- ✓ Only test on `127.0.0.1` (localhost)
- ✓ Test on your own computer/network
- ✓ Use provided Python scripts
- ✓ Disconnect from internet during aggressive tests
- ✓ Inform others on your network

### ⛔ DO NOT:

- ✗ Scan external IPs without permission
- ✗ Attack systems you don't own
- ✗ Test on school/work networks without authorization
- ✗ Use tools against public services
- ✗ Perform tests that could affect others

### 📜 Best Practice:

Use a **virtual machine** for isolated testing:
```
Host Computer
  └── VirtualBox/VMware
      ├── VM1: NIDS Server
      └── VM2: NIDS Client + Attack Tools
```

Benefits:
- Completely isolated network
- Can't accidentally affect real systems
- Easy to reset/snapshot
- Safe for aggressive testing

---

## 🔧 Advanced Testing

### Custom Attack Pattern

```python
# custom_test.py
import socket
import time

target = "127.0.0.1"

# Your custom attack logic
for i in range(1000):
    sock = socket.socket()
    sock.settimeout(0.5)
    try:
        sock.connect((target, 80))
        sock.send(b"Attack payload here")
        sock.close()
    except:
        pass
    time.sleep(0.01)
```

### Real Attack Tools (Use Responsibly)

**Nmap** (Port Scanner)
```bash
nmap -sS -p 1-10000 127.0.0.1
```

**hping3** (Packet Generator)
```bash
hping3 -S -p 80 --flood 127.0.0.1
```

⚠️ **Only on localhost or systems you own!**

---

## 📝 Logging & Debugging

### Enable Verbose Logging

Edit `federated/config.py`:
```python
VERBOSE = True
DEBUG_MODE = True
```

Restart client to see detailed classification info.

### Check Log Files

```bash
# View live logs
tail -f federated/nids.log     # Linux/Mac
Get-Content federated/nids.log -Wait  # Windows PowerShell
```

### API Endpoints for Debugging

- http://localhost:5000/api/status - Server stats
- http://localhost:5000/api/clients - Connected clients
- http://localhost:5000/api/attacks/recent - Attack list
- http://localhost:5000/api/blocked_ips - Blocked IPs
- http://localhost:5000/api/stats/summary - Full summary

---

## 🆘 Common Issues & Fixes

### Issue: "Client not capturing packets"

**Fix:**
- Run client as **Administrator**
- Check antivirus isn't blocking Scapy
- Verify network adapter is active

### Issue: "Server not showing client"

**Fix:**
```bash
# Check server console for registration message
# If missing, client didn't connect properly
# Try restarting both server and client
```

### Issue: "Localhost gets blocked during testing"

**Fix:**
```bash
# In client console, type:
unblock 127.0.0.1

# Or add to whitelist in client.py:
WHITELIST_IPS = {'127.0.0.1', ...}
```

### Issue: "Dashboard shows nothing"

**Fix:**
1. Visit http://localhost:5000/api/status
2. If API works but dashboard doesn't, check browser console (F12)
3. Look for WebSocket connection errors
4. Try different browser

---

## 📚 Further Reading

- `ATTACK_SIMULATION_GUIDE.md` - Complete detailed guide
- `../federated/config.py` - Configuration options
- `../README.md` - Main project documentation

---

## 🎓 Educational Use

These tools are designed for:
- ✅ Learning cybersecurity concepts
- ✅ Testing your own NIDS implementation
- ✅ Understanding attack patterns
- ✅ Demonstrating ML-based detection

Always use ethically and legally! 🛡️

---

**Need Help?**
1. Run `diagnose.py` first
2. Check `ATTACK_SIMULATION_GUIDE.md`
3. Review client/server console logs
4. Verify configuration in `config.py`
