from fastapi.testclient import TestClient
from api.index import app

client = TestClient(app)

def test_health():
    r = client.get("/api/health")
    assert r.status_code == 200 and r.json()["engine"] == "Python"

def test_wordlist_rules():
    r = client.post("/api/wordlist", json={"name":"ishan","dob":"2005","rules":{"leet":True,"years":False,"keyboard":False}})
    assert r.status_code == 200
    assert "ishan" in r.json()["wordlist"]
    assert "ishan2025" not in r.json()["wordlist"]

def test_strength_endpoint():
    r = client.post("/api/analyze", json={"password":"password"})
    assert r.status_code == 200 and r.json()["rating"] == "Very Weak"
    assert "upper bound" in r.json()["entropy_note"]

def test_hash_formats():
    r = client.post("/api/hash-inspect", json={"lines":[
        "alice:$2y$12$abcdefghijklmnopqrstuu12345678901234567890123456789012",
        "bob:1001:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef:::"]})
    assert r.status_code == 200
    assert "bcrypt" in r.json()["entries"][0]["algo"].lower()
    assert r.json()["entries"][1]["format"] == "Windows SAM / NTLM"

def test_dictionary_hash_comparison():
    r = client.post("/api/simulate", json={"account_id":"weak_user","mode":"dictionary","wordlist":["password","ishan123"]})
    assert r.status_code == 200
    assert r.json()["status"] == "cracked" and r.json()["matched"] == "ishan123"
    assert r.json()["attempts"] == 2

def test_bounded_bruteforce_uses_selected_pool():
    r = client.post("/api/simulate", json={"account_id":"demo_short","mode":"bruteforce",
        "pools":{"lower":True,"upper":False,"digits":True,"symbols":False},"max_attempts":100000})
    assert r.status_code == 200
    assert r.json()["status"] == "cracked" and r.json()["matched"] == "ab12"
    assert r.json()["hashes_per_second"] > 0

def test_bruteforce_requires_pool():
    r = client.post("/api/simulate", json={"account_id":"demo_short","mode":"bruteforce","pools":{},"max_attempts":100})
    assert r.status_code == 422

def test_report_has_no_fake_results():
    r = client.post("/api/report", json={"sessions":[],"hashes":[],"wordlist_count":0})
    assert "No simulations have been run" in r.json()["report"]

def test_password_pattern_detection():
    r = client.post("/api/analyze", json={"password":"Abc111xyz1234"})
    assert r.status_code == 200
    issues = " ".join(r.json()["issues"])
    assert "repeated characters" in issues
    assert "sequential number run" in issues

    year_result = client.post("/api/analyze", json={"password":"Abc111xyz2025"})
    assert "year or simple date suffix" in " ".join(year_result.json()["issues"])

def test_health_and_frontend_are_served_locally():
    page = client.get("/")
    assert page.status_code == 200
    assert "AegisVault" in page.text
