# 📈 Why Timeline Chart Shows No Data

## Quick Answer

The **Attack Timeline (Real-time)** chart groups attacks by **minute**. If all your test attacks happen within the same minute, they appear as only **ONE data point**, which looks like an empty chart!

---

## ✅ SOLUTION: Run This Script

```bash
python testing\fix_timeline_chart.py
```

This sends **1 attack every 10 seconds for 2 minutes**, creating multiple time points.

**Result:** Timeline chart will show a proper line graph with 12+ data points!

---

## Why This Happens

### How Timeline Chart Works:

1. Dashboard receives attacks from server
2. Groups attacks by **HH:MM** (minute)  
3. Plots count per minute on graph

### The Problem:

```
Attack 1: 14:32:10  →  Groups to 14:32  ┐
Attack 2: 14:32:15  →  Groups to 14:32  ├─→ ONE point (3 attacks)
Attack 3: 14:32:45  →  Groups to 14:32  ┘

Result: Chart shows 1 point at 14:32
```

### What You Need:

```
Attack 1: 14:30:xx  →  Point at 14:30
Attack 2: 14:31:xx  →  Point at 14:31
Attack 3: 14:32:xx  →  Point at 14:32

Result: Chart shows 3 points (trend line visible!)
```

---

## Quick Fixes

### Option 1: Use the Fixer Script (Recommended)
```bash
python testing\fix_timeline_chart.py
```
- Sends attacks every 10 seconds
- Takes 2 minutes
- Creates nice timeline

### Option 2: Run Port Scan, Wait, Run Again
```bash
# Run first scan
python testing\test_portscan.py

# Wait 2-3 minutes

# Run second scan  
python testing\test_portscan.py

# Refresh dashboard
```

### Option 3: Let Real Traffic Accumulate
- Keep client running
- Browse websites, download files
- Over hours, legitimate attacks (if any) will show on timeline

---

## What The Timeline Chart Should Look Like

**Empty (1 data point):**
```
  |
1 |     ●
  |_____________
    14:32
```

**Properly Filled (multiple points):**
```
   |
3  |           ●
2  |     ●   ●   ●
1  |   ●   ●       ●
   |_________________
     14:30-14:35
```

---

## Code Reference

**Dashboard JavaScript** (dashboard.html):
```javascript
function updateTimelineChart() {
    // Group attacks by time
    const grouped = {};
    
    attacksData.forEach(attack => {
        const time = attack.timestamp.substring(11, 16); // HH:MM ← THIS!
        grouped[time] = (grouped[time] || 0) + 1;
    });
    
    const times = Object.keys(grouped).sort().slice(-15); // Last 15 minutes
    const counts = times.map(t => grouped[t]);
    
    attackTimelineChart.data.labels = times;
    attackTimelineChart.data.datasets[0].data = counts;
    attackTimelineChart.update();
}
```

The key is `substring(11, 16)` which extracts **HH:MM** (minute precision).

---

## Alternative: Change Chart to Show Seconds

If you want **immediate** results, modify the dashboard to group by **HH:MM:SS** instead:

**Edit:** `dashboard/templates/dashboard.html`

**Find** (around line 540):
```javascript
const time = attack.timestamp.substring(11, 16); // HH:MM
```

**Change to:**
```javascript
const time = attack.timestamp.substring(11, 19); // HH:MM:SS
```

**Then restart server** and attacks will appear as individual points!

⚠️ But this makes the chart show only ~30 seconds of data (too zoomed in).

---

## Summary

✅ **Timeline chart works correctly**  
✅ **It's designed for minute-level aggregation**  
✅ **You need attacks across different minutes**  

🎯 **Easiest fix:** `python testing\fix_timeline_chart.py`

---

Need help? The chart populates automatically as attacks occur over time!
