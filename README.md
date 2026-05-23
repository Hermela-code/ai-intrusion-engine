# AI Network Intrusion Detection & Prevention System

This project is a prototype of an AI-powered Network Intrusion Detection and Prevention System (IDPS). It captures live network traffic, uses a pre-trained Random Forest Machine Learning model to identify potential threats, logs incident alerts to a database, and displays them on a live web dashboard.

## System Components

* **`train_real_model.py`**: Trains the machine learning model using the NSL-KDD dataset.
* **`init_db.py`**: Creates the SQLite database to store security logs and statistics.
* **`sniffer.py`**: The core engine. It intercepts raw network packets, extracts features, queries the ML model, logs threats to the database, and blocklists malicious IPs.
* **`app.py`**: Spins up the local Flask web server.
* **`templates/index.html`**: The UI dashboard that reads data from the database and updates in real-time.

---

## How to Set Up and Run

Follow these steps in order to get the project running locally on a Linux machine (Debian/Ubuntu).

### 1. Installation & Environment Setup
Open your terminal, navigate into this project folder, and set up your dependencies:

```bash
# Create a virtual environment
python3 -m venv idps_env

# Activate the environment
source idps_env/bin/activate

# Install required tools
pip install pandas scikit-learn joblib scapy flask
```
### 2. Initialize the Database

Run this script once to create the local idps.db file and its required data tables:
```bash
python3 init_db.py
```
### 3. Start the Network Sensor (Terminal 1)

Because analyzing raw network card traffic requires root privileges, you must run the sniffer script using sudo. Use the absolute path to ensure Python finds your installed modules:
```bash
sudo /home/username/idps_env/bin/python /home/username/sniffer.py
```
Leave this terminal window open. It will print status updates as it evaluates network packets.

### 4. Launch the Web Dashboard (Terminal 2)

Open a new terminal window or tab, activate your environment, and start the web server:

```bash
source idps_env/bin/activate
python app.py
```
Once running, open your web browser and go to: http://127.0.0.1:5000

### Dashboard Preview

When the system is running and detecting traffic, your local dashboard will dynamically display background statistics and actively flag security threats like this:

<img width="1918" height="1054" alt="image" src="https://github.com/user-attachments/assets/7516faf4-cc84-40f5-a72a-d62b4568ba6d" />




