"""
PhishGuard - Phishing URL Detection System
A beginner-friendly, rule-based URL analyser with a Tkinter GUI.

This tool checks URL patterns only. 
"""

import re
import ipaddress
import tkinter as tk
from tkinter import ttk
from urllib.parse import urlparse, unquote


# --------------------------- Detection engine --------------------------- #

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at"
}

SUSPICIOUS_TLDS = {
    "zip", "mov", "click", "top", "xyz", "work", "country",
    "gq", "tk", "ml", "cf", "ga"
}

SUSPICIOUS_WORDS = {
    "login", "signin", "verify", "verification", "update",
    "secure", "account", "password", "banking", "wallet",
    "payment", "confirm", "free", "gift", "bonus", "urgent"
}


def analyse_url(raw_url):
    """Return a risk score, category, and human-readable reasons."""
    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("Please enter a URL first.")

    if any(ch.isspace() for ch in raw_url):
        raise ValueError("The URL cannot contain spaces.")

    # Add a scheme if the user enters only a domain name.
    candidate = raw_url if "://" in raw_url else "https://" + raw_url
    parsed = urlparse(candidate)

    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs can be checked.")

    if not parsed.hostname:
        raise ValueError("That does not look like a valid website URL.")

    host = parsed.hostname.lower().rstrip(".")
    if not host or "." not in host:
        raise ValueError("Please enter a complete domain, such as example.com.")

    score = 0
    reasons = []

    def flag(points, message):
        nonlocal score
        score += points
        reasons.append((points, message))

    if parsed.scheme.lower() != "https":
        flag(8, "The URL does not use HTTPS encryption.")

    if "@" in parsed.netloc:
        flag(25, "The @ symbol can hide the real destination of a URL.")

    try:
        ipaddress.ip_address(host)
        flag(30, "The website uses a raw IP address instead of a domain name.")
    except ValueError:
        pass

    if "xn--" in host:
        flag(20, "The domain contains punycode, which can be used for look-alike names.")

    if host in SHORTENERS:
        flag(15, "The URL uses a known link-shortening service, hiding its destination.")

    labels = host.split(".")
    if len(labels) >= 5:
        flag(12, "The domain has an unusually large number of subdomains.")

    if host.count("-") >= 3:
        flag(8, "The domain contains many hyphens.")

    if len(raw_url) > 100:
        flag(8, "The URL is unusually long.")
    elif len(raw_url) > 75:
        flag(4, "The URL is quite long.")

    tld = labels[-1] if labels else ""
    if tld in SUSPICIOUS_TLDS:
        flag(12, f"The .{tld} domain ending is commonly associated with higher-risk registrations.")

    try:
        port = parsed.port
        if port and port not in (80, 443):
            flag(10, f"The URL uses an unusual port ({port}).")
    except ValueError:
        flag(10, "The URL contains an invalid port number.")

    decoded_url = unquote(raw_url).lower()
    found_words = sorted(word for word in SUSPICIOUS_WORDS if word in decoded_url)
    if found_words:
        shown = ", ".join(found_words[:5])
        flag(5 if len(found_words) == 1 else 9,
             f"Contains words often used in deceptive links: {shown}.")

    # A username/password in the URL is unusual for an ordinary public link.
    if parsed.username or parsed.password:
        flag(20, "The URL contains embedded username or password information.")

    score = min(score, 100)

    if score >= 40:
        category = "HIGH RISK"
        advice = "Avoid opening this link. Do not enter passwords, OTPs or payment details."
    elif score >= 18:
        category = "SUSPICIOUS"
        advice = "Be careful. Verify the website address using its official source."
    else:
        category = "LOW RISK"
        advice = "No major warning signs were found by these checks. This does not prove the site is safe."

    if not reasons:
        reasons = [(0, "No obvious suspicious URL patterns were detected.")]

    return {
        "url": raw_url,
        "host": host,
        "score": score,
        "category": category,
        "advice": advice,
        "reasons": reasons,
    }


# ------------------------------- GUI ------------------------------------ #

BG = "#0b1220"
PANEL = "#121d30"
PANEL_LIGHT = "#18263c"
TEXT = "#edf4ff"
MUTED = "#9aabc2"
ACCENT = "#27d3b2"
GREEN = "#35c98a"
YELLOW = "#f4bd50"
RED = "#ff667d"
BORDER = "#263852"


class PhishGuardApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PhishGuard | URL Security Scanner")
        self.root.geometry("960x720")
        self.root.minsize(780, 650)
        self.root.configure(bg=BG)

        self.history = []
        self.last_result = None

        self.build_ui()
        self.root.bind("<Return>", lambda _event: self.scan_url())

    def build_ui(self):
        # Header
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=30, pady=(22, 12))

        logo = tk.Label(
            header, text="🛡", font=("Segoe UI Emoji", 27),
            bg=BG, fg=ACCENT
        )
        logo.pack(side="left", padx=(0, 12))

        title_area = tk.Frame(header, bg=BG)
        title_area.pack(side="left")

        tk.Label(
            title_area, text="PHISHGUARD", font=("Segoe UI", 22, "bold"),
            bg=BG, fg=TEXT
        ).pack(anchor="w")

        tk.Label(
            title_area, text="PHISHING URL DETECTION SYSTEM",
            font=("Segoe UI", 9, "bold"), bg=BG, fg=MUTED
        ).pack(anchor="w")

        tk.Label(
            header, text="●  SYSTEM READY", font=("Segoe UI", 9, "bold"),
            bg=BG, fg=GREEN
        ).pack(side="right", pady=12)

        # Intro
        tk.Label(
            self.root, text="Check a link before you trust it.",
            font=("Segoe UI", 17, "bold"), bg=BG, fg=TEXT
        ).pack(anchor="w", padx=32, pady=(12, 4))

        tk.Label(
            self.root,
            text="Enter a website URL below. PhishGuard checks for common suspicious patterns.",
            font=("Segoe UI", 10), bg=BG, fg=MUTED
        ).pack(anchor="w", padx=32, pady=(0, 18))

        # Scanner panel
        scanner = tk.Frame(
            self.root, bg=PANEL, highlightbackground=BORDER,
            highlightthickness=1
        )
        scanner.pack(fill="x", padx=30, pady=(0, 16))

        tk.Label(
            scanner, text="  WEBSITE URL", font=("Segoe UI", 9, "bold"),
            bg=PANEL, fg=MUTED
        ).pack(anchor="w", padx=18, pady=(16, 7))

        input_row = tk.Frame(scanner, bg=PANEL)
        input_row.pack(fill="x", padx=18, pady=(0, 12))

        self.url_entry = tk.Entry(
            input_row, font=("Segoe UI", 12), bg="#0c1728", fg=TEXT,
            insertbackground=TEXT, relief="flat",
            highlightthickness=1, highlightbackground=BORDER,
            highlightcolor=ACCENT
        )
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=12, padx=(0, 10))
        self.url_entry.insert(0, "https://example.com")

        self.scan_button = tk.Button(
            input_row, text="  SCAN URL  ", command=self.scan_url,
            font=("Segoe UI", 10, "bold"), bg=ACCENT, fg="#07151b",
            activebackground="#54e5c9", activeforeground="#07151b",
            relief="flat", cursor="hand2", padx=12, pady=11
        )
        self.scan_button.pack(side="left")

        action_row = tk.Frame(scanner, bg=PANEL)
        action_row.pack(fill="x", padx=18, pady=(0, 15))

        self.small_button(action_row, "Try suspicious example", self.load_example).pack(side="left")
        self.small_button(action_row, "Clear", self.clear_all).pack(side="left", padx=8)

        # Result panel
        self.result_panel = tk.Frame(
            self.root, bg=PANEL, highlightbackground=BORDER,
            highlightthickness=1
        )
        self.result_panel.pack(fill="both", expand=True, padx=30, pady=(0, 14))

        result_header = tk.Frame(self.result_panel, bg=PANEL)
        result_header.pack(fill="x", padx=18, pady=(15, 8))

        tk.Label(
            result_header, text="SCAN RESULTS", font=("Segoe UI", 10, "bold"),
            bg=PANEL, fg=TEXT
        ).pack(side="left")

        self.status_label = tk.Label(
            result_header, text="WAITING FOR SCAN",
            font=("Segoe UI", 9, "bold"), bg=PANEL, fg=MUTED
        )
        self.status_label.pack(side="right")

        # Risk score and category
        score_row = tk.Frame(self.result_panel, bg=PANEL)
        score_row.pack(fill="x", padx=18, pady=(4, 10))

        self.score_label = tk.Label(
            score_row, text="--", font=("Segoe UI", 31, "bold"),
            bg=PANEL, fg=TEXT
        )
        self.score_label.pack(side="left")

        self.category_label = tk.Label(
            score_row, text="No scan yet", font=("Segoe UI", 13, "bold"),
            bg=PANEL, fg=MUTED
        )
        self.category_label.pack(side="left", padx=14, pady=(8, 0))

        # Progress bar
        self.progress = ttk.Progressbar(
            self.result_panel, maximum=100, mode="determinate",
            style="Risk.Horizontal.TProgressbar"
        )
        self.progress.pack(fill="x", padx=18, pady=(0, 12))

        tk.Label(
            self.result_panel, text="DETECTION DETAILS",
            font=("Segoe UI", 9, "bold"), bg=PANEL, fg=MUTED
        ).pack(anchor="w", padx=18, pady=(3, 6))

        self.details = tk.Text(
            self.result_panel, height=6, wrap="word",
            font=("Segoe UI", 10), bg="#0c1728", fg=TEXT,
            insertbackground=TEXT, relief="flat",
            padx=12, pady=10, state="disabled"
        )
        self.details.pack(fill="both", expand=True, padx=18, pady=(0, 10))
        self.details.tag_configure("good", foreground=GREEN)
        self.details.tag_configure("warn", foreground=YELLOW)
        self.details.tag_configure("bad", foreground=RED)
        self.details.tag_configure("muted", foreground=MUTED)

        self.advice_label = tk.Label(
            self.result_panel, text="Your scan summary will appear here.",
            font=("Segoe UI", 9), bg=PANEL, fg=MUTED,
            wraplength=820, justify="left"
        )
        self.advice_label.pack(anchor="w", padx=18, pady=(0, 14))

        # Footer / history
        footer = tk.Frame(self.root, bg=BG)
        footer.pack(fill="x", padx=30, pady=(0, 16))

        tk.Label(
            footer, text="RECENT SCANS", font=("Segoe UI", 9, "bold"),
            bg=BG, fg=MUTED
        ).pack(side="left")

        self.history_label = tk.Label(
            footer, text="No scans yet",
            font=("Segoe UI", 9), bg=BG, fg=MUTED
        )
        self.history_label.pack(side="right")

        tk.Label(
            self.root,
            text="PHISHGUARD  •  Educational project  •  Pattern-based checks only",
            font=("Segoe UI", 8), bg=BG, fg="#64758d"
        ).pack(pady=(0, 10))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure(
            "Risk.Horizontal.TProgressbar",
            troughcolor="#263852", background=ACCENT,
            bordercolor=PANEL, lightcolor=ACCENT, darkcolor=ACCENT,
            thickness=10
        )

    def small_button(self, parent, label, command):
        return tk.Button(
            parent, text=label, command=command,
            font=("Segoe UI", 9), bg=PANEL_LIGHT, fg=TEXT,
            activebackground="#263852", activeforeground=TEXT,
            relief="flat", cursor="hand2", padx=10, pady=6
        )

    def scan_url(self):
        try:
            result = analyse_url(self.url_entry.get())
        except ValueError as error:
            self.status_label.config(text="INPUT REQUIRED", fg=YELLOW)
            self.show_details([(0, str(error))], "warn")
            return

        self.last_result = result
        self.history.insert(0, f"{result['host']} — {result['category']}")
        self.history = self.history[:5]
        self.history_label.config(text="  |  ".join(self.history))

        score = result["score"]
        category = result["category"]

        if category == "HIGH RISK":
            color, tag = RED, "bad"
        elif category == "SUSPICIOUS":
            color, tag = YELLOW, "warn"
        else:
            color, tag = GREEN, "good"

        self.status_label.config(text="SCAN COMPLETE", fg=GREEN)
        self.score_label.config(text=f"{score}/100")
        self.category_label.config(text=category, fg=color)
        self.progress.configure(value=score)
        ttk.Style().configure(
            "Risk.Horizontal.TProgressbar",
            background=color, lightcolor=color, darkcolor=color
        )

        self.show_details(result["reasons"], tag)
        self.advice_label.config(text=result["advice"], fg=color)

    def show_details(self, reasons, default_tag):
        self.details.config(state="normal")
        self.details.delete("1.0", "end")

        for points, message in reasons:
            prefix = "• " if points == 0 else f"• +{points}  "
            self.details.insert("end", prefix + message + "\n", default_tag)

        self.details.config(state="disabled")

    def load_example(self):
        self.url_entry.delete(0, "end")
        self.url_entry.insert(0, "http://secure-login-account-verify.example.zip/login")

    def clear_all(self):
        self.url_entry.delete(0, "end")
        self.score_label.config(text="--")
        self.category_label.config(text="No scan yet", fg=MUTED)
        self.status_label.config(text="WAITING FOR SCAN", fg=MUTED)
        self.progress.configure(value=0)
        self.show_details([], "muted")
        self.advice_label.config(text="Your scan summary will appear here.", fg=MUTED)
        self.last_result = None
        self.url_entry.focus_set()


if __name__ == "__main__":
    root = tk.Tk()
    app = PhishGuardApp(root)
    root.mainloop()
