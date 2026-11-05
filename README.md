# 🛡️ PhishGuard

Python-Based Rule-Based Phishing URL Detection Desktop Application

PhishGuard is a beginner-friendly cybersecurity desktop application developed using Python and Tkinter. It analyses URLs for suspicious patterns, calculates a risk score, and classifies them into different risk categories.

The application aims to improve awareness of phishing links by explaining the warning signs detected in a submitted URL.

✨ Features

- URL input and validation
- Rule-based phishing URL analysis
- Weighted risk scoring system (0–100)
- Three risk categories:
  - 🟢 LOW RISK
  - 🟡 SUSPICIOUS
  - 🔴 HIGH RISK
- Detailed detection reasons
- Built-in suspicious URL example
- Recent scan history (up to five scans)
- User-friendly graphical interface
- Input validation and error handling

🛠️ Technologies Used

Technology| Purpose
Python| Core programming language
Tkinter| Graphical user interface
urllib.parse| URL parsing
ipaddress| IP address validation
re| Imported regular-expression module

⚙️ How It Works

1. The user enters a URL.
2. PhishGuard validates the input.
3. The application checks predefined suspicious URL indicators.
4. Each detected indicator contributes weighted risk points.
5. The total score is calculated and capped at 100.
6. A risk category and explanation are displayed.

📊 Risk Classification

Score| Category
0–17| LOW RISK
18–39| SUSPICIOUS
40–100| HIGH RISK

💻 Installation and Usage

Requirements: Python 3 with Tkinter.

1. Clone the repository:

git clone https://github.com/SaniyaKadam0022/PhishGuard.git

2. Open the project folder:

cd PhishGuard

3. Run the application:

python main.py

No third-party Python packages are required.

📁 Project Structure

PhishGuard/
│
├── main.py
├── README.md
└── PhishGuard_Project_Report.pdf

⚠️ Limitations

- Uses predefined rules rather than machine learning.
- Does not connect to live phishing databases.
- Does not inspect website content or redirects.
- May produce false positives and false negatives.
- A LOW RISK result does not guarantee that a website is safe.

🚀 Future Enhancements

- Integration with phishing threat-intelligence APIs.
- Redirect inspection.
- Advanced domain analysis.
- Exportable scan reports.
- Automated unit testing.

👩‍💻 Author

Ms. Saniya Sudhir Kadam



---

PhishGuard is an educational URL analysis tool and should not be considered a complete website security solution.
