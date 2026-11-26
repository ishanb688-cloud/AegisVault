import hashlib
from fastapi.testclient import TestClient
from app import app

client = TestClient(app)

def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "online"

def test_unified_sha256_match():
    digest = hashlib.sha256(b"LabPass123!").hexdigest()
    response = client.post("/api/assessment", json={
        "records": [f"labuser:{digest}:20000:0:99999:7:::"],
        "candidate_words": ["LabPass123!"],
        "include_common_candidates": False,
    })
    assert response.status_code == 200
    item = response.json()["findings"][0]
    assert item["verification"]["status"] == "verified_match"
    assert item["password_quality"]["length"] == len("LabPass123!")
    assert digest not in response.text

def test_unmatched_candidate_does_not_claim_strong():
    digest = hashlib.sha256(b"not-in-list").hexdigest()
    response = client.post("/api/assessment", json={
        "records": [f"labuser:{digest}:20000:0:99999:7:::"],
        "candidate_words": ["different"],
        "include_common_candidates": False,
    })
    item = response.json()["findings"][0]
    assert item["verification"]["status"] == "not_found_in_candidates"
    assert item["password_quality"] is None

def test_ntlm_is_identified_but_not_verified():
    response = client.post("/api/assessment", json={
        "records": ["student:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::"],
        "include_common_candidates": False,
    })
    item = response.json()["findings"][0]
    assert item["hash_info"]["algorithm"] == "MD5 or NTLM (ambiguous)"
    assert item["verification"]["status"] == "not_verified"

def test_locked_linux_account():
    response = client.post("/api/assessment", json={
        "records": ["student:!$y$j9T$locked:20000:0:99999:7:::"]
    })
    item = response.json()["findings"][0]
    assert item["verification"]["status"] == "not_testable"
