# 🛡️ Real-Time Cyber Threat Detection Using Federated Machine Learning

A real-time network intrusion detection system that combines **federated learning**, **ensemble machine learning**, and **explainable AI** to detect and respond to cyber attacks across distributed clients — visualized through a live web dashboard.

---

## 🏗️ System Architecture


```
                 Network Traffic
                        │
                        ▼
              ┌─────────────────────┐
              │  Federated Clients   │
              │ (Local Detection &   │
              │  Model Training)     │
              └──────────┬───────────┘
                         │
                  Model Updates
                         │
                         ▼
              ┌─────────────────────┐
              │ Federated Learning  │
              │       Server        │
              └──────────┬──────────┘
                         │
                   Global Model
                         │
              ┌──────────┴──────────┐
              ▼                     ▼
     ┌─────────────────┐   ┌────────────────────┐
     │ Threat Detection │   │  Real-Time         │
     │ & Classification │   │  Monitoring        │
     └────────┬─────────┘   └─────────┬──────────┘
              │                       │
              ▼                       ▼
     ┌─────────────────┐   ┌────────────────────┐
     │ IP Blocking &   │   │  Web Dashboard      │
     │ Alert Generation│   │  & Visualization    │
     └─────────────────┘   └────────────────────┘
```

---

## 🔄 How the System Works

1. Network traffic is captured and processed.
2. Traffic is converted into usable flow-based features.
3. The machine-learning detection pipeline analyzes the traffic.
4. Suspicious traffic is classified into supported attack categories.
5. Attack information is sent to the monitoring server.
6. The dashboard displays the detected attack in real time.
7. Suspicious IP addresses can be added to the blocked-IP list.
8. Federated clients participate in the distributed learning workflow.
9. Global model updates are synchronized through the federated server.
10. SHAP analysis explains which features drove each model decision.

---

## 🧠 Machine Learning Approach

The detection pipeline uses **ensemble classification**, combining:

- Random Forest
- Extra Trees
- LightGBM
- Scikit-learn-based ML utilities
- Voting / ensemble-based detection

### Supported Attack Categories

- BruteForce
- DoS / DDoS
- PortScan

Each detection event is logged with a confidence score. Example event:

```
Attack Type: BruteForce
Source:      192.168.100.27
Client:      sim_node_1
Confidence:  77.0%
```

---

## 🔐 Federated Learning

Federated learning lets multiple distributed clients collaborate on model training **without** centralizing raw traffic data.

```
Client 1 ─────┐
              │
Client 2 ─────┼──► Federated Server ───► Global Model
              │
Client 3 ─────┘
```

Each client processes local traffic and contributes to the model-update workflow. The central server coordinates participating clients and pushes global model updates back down to the monitoring layer — improving detection collaboratively while keeping raw data decentralized.

---

## 🔎 Explainable AI

The system integrates **SHAP (SHapley Additive exPlanations)** for model interpretability, going beyond a binary "attack detected" flag.

**Capabilities:**
- Feature importance analysis
- Model prediction interpretation
- Visualization of influential features
- Improved transparency of threat-detection decisions

---

## 🖥️ Real-Time Dashboard

Built with **Flask** and **Socket.IO**, the dashboard provides a live operational view of the system.

**Metrics tracked:**
- Connected federated clients
- Total attacks
- Blocked IPs
- Packets processed
- Federated round
- Global model accuracy
- Attack type distribution
- Attack timeline
- Live attack feed
- Client-level statistics

---

## 📸 Screenshots

| Dashboard Overview | Attack Timeline | Live Attack Feed |
|---|---|---|
| ![Dashboard Overview](assets/screenshots/dashboard-overview.png) | ![Attack Timeline](assets/screenshots/attack-timeline.png) | ![Live Attack Feed](assets/screenshots/live-attack-feed.png) |

- **Dashboard Overview** — federated NIDS status, model accuracy, attack counts, blocked IPs, packets processed, and attack distribution.
- **Attack Timeline** — detected attack activity over time.
- **Live Attack Feed** — attack type, source IP, federated client, confidence, and timestamp per event, plus a blocked-IP panel.
- **Connected Federated Clients** — per-client status, attacks detected, packets processed, and blocked IPs.

---

## 🛠️ Tech Stack

**Backend**
- Python
- Flask 3.0.0
- Flask-SocketIO 5.3.5
- Flask-CORS 4.0.0
- Python-SocketIO 5.10.0

**Machine Learning**
- Scikit-learn 1.6.1
- LightGBM 4.1.0
- Joblib 1.3.2
- NumPy 1.26.3
- Pandas 2.0.3

**Network Security**
- Scapy 2.5.0

**Explainable AI**
- SHAP 0.44.0

**Visualization**
- Matplotlib 3.7.2
- Seaborn 0.12.2

---

## 📁 Project Structure

```
CYBERPROJ/
│
├── analysis/
├── dashboard/
├── data/
├── federated/
├── models/
├── preprocessing/
├── reports/
├── testing/
├── training/
│
├── .gitignore
├── OPTIMIZATION_GUIDE.md
├── PERFORMANCE_ANALYSIS.md
├── README.md
├── requirements.txt
└── test_blocking_speed.py
```

> `myvenv/` (local virtual environment) is excluded from version control via `.gitignore`.

---

## ⚙️ Installation

**1. Clone the repository**
```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd CYBERPROJ
```

**2. Create a virtual environment**
```bash
python -m venv myvenv
```

**3. Activate the virtual environment**

Windows PowerShell:
```powershell
myvenv\Scripts\Activate.ps1
```

Windows Command Prompt:
```cmd
myvenv\Scripts\activate
```

**4. Install dependencies**
```bash
pip install -r requirements.txt
```

---

## ▶️ How to Run

**Start the federated server**
```bash
python federated/server.py
```

**Start the simulation client** (in a separate terminal)
```bash
python federated/simulation_client.py
```

**Open the dashboard**

Visit [http://127.0.0.1:5001/](http://127.0.0.1:5001/) in your browser.

---

## 📊 Results

The live dashboard exposes real-time operational metrics, including federated client status, detected attack counts, blocked IPs, packets processed, attack-type distribution, attack timeline, source information, detection confidence, client-level statistics, and global model accuracy.

### Example Runtime State

| Metric | Value |
|---|---|
| Federated Round | 0 |
| Global Model Accuracy | 99.67% |
| Connected Clients | 1 |
| Total Attacks | 536 |
| Blocked IPs | 134 |
| Packets Processed | 295 |

> These are example runtime values and will vary between executions.

---

## 🧪 Testing

Testing utilities are located in `testing/` and cover:

- Dashboard injection testing
- Port scan testing
- Traffic flood testing
- Diagnostic utilities
- Blocking-speed testing

---

## 📚 Project Documentation

- [`OPTIMIZATION_GUIDE.md`](OPTIMIZATION_GUIDE.md)
- [`PERFORMANCE_ANALYSIS.md`](PERFORMANCE_ANALYSIS.md)
- [`SPEED_ENHANCEMENT_SUMMARY.md`](SPEED_ENHANCEMENT_SUMMARY.md)

---

## 🔮 Future Scope

- Deployment across multiple real network nodes
- Real-time packet capture from production networks
- Integration with enterprise firewalls
- Automated firewall rule generation
- More attack categories
- Advanced anomaly detection
- Larger federated client deployments
- Edge-device deployment
- Stronger secure aggregation mechanisms
- Continuous threat-intelligence integration
- Improved model personalization for individual clients

---

## 📖 References

Research referenced in the project report spans network intrusion detection, flow-based intrusion detection, federated learning, deep learning for cybersecurity, explainable AI, autoencoder-based anomaly detection, and distributed cybersecurity systems more broadly — including work on temporal NetFlow analysis and botnet detection.

---

## ⚠️ Disclaimer

This project is intended for **academic, research, and controlled testing environments only**.

Only perform network monitoring, traffic generation, attack simulation, or IP blocking on systems and networks for which you have **explicit authorization**.

---

## 📄 License

This project is currently intended for academic and educational purposes. Add a formal open-source license if you decide to distribute it publicly.
