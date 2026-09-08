from flask import Flask, request, jsonify
from androguard.core.bytecodes.apk import APK
import os, tempfile

app = Flask(__name__)

DANGEROUS_PERMISSIONS = [
    "READ_SMS", "SEND_SMS", "READ_CONTACTS", "RECORD_AUDIO",
    "CAMERA", "ACCESS_FINE_LOCATION", "READ_CALL_LOG",
    "WRITE_EXTERNAL_STORAGE", "SYSTEM_ALERT_WINDOW"
]

def analyze_apk(path):
    apk = APK(path)
    issues = []

    if apk.get_attribute_value("application", "debuggable") == "true":
        issues.append({"severity": "high", "issue": "App debuggable=true hai — production build mein disable karo."})

    if apk.get_attribute_value("application", "allowBackup") != "false":
        issues.append({"severity": "medium", "issue": "allowBackup disabled nahi hai — data leak risk (adb backup se data nikal sakte hain)."})

    if apk.get_attribute_value("application", "usesCleartextTraffic") == "true":
        issues.append({"severity": "high", "issue": "Cleartext (HTTP) traffic allowed hai — sab traffic HTTPS pe force karo."})

    target_sdk = int(apk.get_target_sdk_version() or 0)
    if target_sdk < 35:
        issues.append({"severity": "high", "issue": f"Target SDK {target_sdk} hai — Play Store ko Aug 2026 se minimum 35+ chahiye, warna naye users ko app nahi dikhega."})

    for comp_type in ["activity", "service", "receiver"]:
        for comp in apk.get_elements(comp_type, "name"):
            exported = apk.get_attribute_value(comp_type, "exported", name=comp)
            perm = apk.get_attribute_value(comp_type, "permission", name=comp)
            if exported == "true" and not perm:
                issues.append({"severity": "medium", "issue": f"{comp_type} '{comp}' exported hai bina permission check ke — security risk."})

    used_perms = apk.get_permissions()
    for perm in used_perms:
        for dp in DANGEROUS_PERMISSIONS:
            if dp in perm:
                issues.append({"severity": "low", "issue": f"Sensitive permission use ho rahi hai: {perm} — zaroorat confirm karo."})

    size_mb = os.path.getsize(path) / (1024*1024)
    if size_mb > 50:
        issues.append({"severity": "low", "issue": f"APK size {size_mb:.1f}MB hai — optimize karo (App Bundle .aab use karo)."})

    return {
        "app_name": apk.get_app_name(),
        "package": apk.get_package(),
        "target_sdk": target_sdk,
        "total_issues": len(issues),
        "issues": issues
    }

@app.route("/scan", methods=["POST"])
def scan():
    file = request.files.get("apk")
    if not file:
        return jsonify({"error": "APK file nahi mila"}), 400

    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
        file.save(tmp.name)
        try:
            result = analyze_apk(tmp.name)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        finally:
            os.unlink(tmp.name)

    return jsonify(result)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
