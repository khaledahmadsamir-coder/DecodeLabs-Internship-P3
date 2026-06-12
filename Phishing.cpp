// ============================================================
// DecodeLabs Cybersecurity Internship | Batch 2026
// Project 3: Phishing Awareness Analysis
// Analyze emails/messages for phishing indicators
// ============================================================

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <sstream>

using namespace std;







const string RESET = "\033[0m";
const string BOLD = "\033[1m";
const string CYAN = "\033[1;36m";
const string GREEN = "\033[1;32m";
const string YELLOW = "\033[1;33m";
const string RED = "\033[1;31m";

// ── Analysis Result ──────────────────────────────────────────
struct AnalysisResult {
    bool phishingDetected;
    int riskScore;
    vector<string> redFlags;
};

// ── Convert to lowercase ─────────────────────────────────────
string toLower(string text) {
    transform(text.begin(), text.end(),
        text.begin(), ::tolower);
    return text;
}

// ── Core Analysis ────────────────────────────────────────────
AnalysisResult analyzeMessage(const string& message) {

    AnalysisResult result;
    result.phishingDetected = false;
    result.riskScore = 0;

    string lower = toLower(message);

    vector<string> suspiciousKeywords = {
        "urgent",
        "verify",
        "password",
        "bank",
        "login",
        "click here",
        "account suspended",
        "free money",
        "winner",
        "claim now",
        "security alert",
        "limited time"
    };

    for (const string& keyword : suspiciousKeywords) {

        if (lower.find(keyword) != string::npos) {

            result.redFlags.push_back(
                "Suspicious keyword detected: \"" + keyword + "\""
            );

            result.riskScore++;
        }
    }

    // URL detection
    if (lower.find("http://") != string::npos ||
        lower.find("https://") != string::npos) {

        result.redFlags.push_back(
            "Contains a clickable link."
        );

        result.riskScore += 2;
    }

    // Email asking for credentials
    if (lower.find("password") != string::npos ||
        lower.find("pin") != string::npos ||
        lower.find("otp") != string::npos) {

        result.redFlags.push_back(
            "Requests sensitive credentials."
        );

        result.riskScore += 2;
    }

    result.phishingDetected = result.riskScore >= 3;

    return result;
}

// ── Risk Level ───────────────────────────────────────────────
string getRiskLevel(int score) {

    if (score <= 2)
        return "LOW";

    if (score <= 5)
        return "MEDIUM";

    return "HIGH";
}

// ── Display Header ───────────────────────────────────────────
void printHeader() {

    cout << CYAN
        << "╔══════════════════════════════════════════╗\n"
        << "║ DecodeLabs - Phishing Awareness Analyzer ║\n"
        << "║        Batch 2026 | Project 3            ║\n"
        << "╚══════════════════════════════════════════╝\n"
        << RESET << "\n";
}

// ── Print Result ─────────────────────────────────────────────
void printResult(const AnalysisResult& result) {

    cout << "\n";
    cout << "──────────────────────────────────────────\n";

    cout << BOLD
        << "Risk Score : "
        << result.riskScore
        << RESET << "\n";

    string risk = getRiskLevel(result.riskScore);

    if (risk == "LOW")
        cout << GREEN;

    else if (risk == "MEDIUM")
        cout << YELLOW;

    else
        cout << RED;

    cout << "Risk Level : " << risk << RESET << "\n\n";

    if (result.redFlags.empty()) {

        cout << GREEN
            << "[+] No phishing indicators detected.\n"
            << RESET;
    }
    else {

        cout << RED
            << "[!] Red Flags Found:\n"
            << RESET;

        for (const string& flag : result.redFlags) {
            cout << "   • " << flag << "\n";
        }
    }

    cout << "\n";

    if (result.phishingDetected) {

        cout << RED
            << "Message Classification: POTENTIAL PHISHING\n"
            << RESET;

        cout << "Reason:\n";
        cout << "The message contains suspicious language,\n";
        cout << "links, or credential requests commonly\n";
        cout << "used in phishing attacks.\n";
    }
    else {

        cout << GREEN
            << "Message Classification: APPEARS SAFE\n"
            << RESET;
    }

    cout << "──────────────────────────────────────────\n";
}

int main() {

    printHeader();

    char again = 'Y';

    while (again == 'Y' || again == 'y') {

        string message;

        cout << BOLD
            << "Paste email/message:\n"
            << RESET;

        getline(cin, message);

        AnalysisResult result =
            analyzeMessage(message);

        printResult(result);

        cout << "\nAnalyze another message? (Y/N): ";
        cin >> again;
        cin.ignore();

        cout << "\n";
    }

    cout << CYAN
        << "Threat identified successfully! "
        << "- DecodeLabs 2026\n"
        << RESET;

    return 0;
}