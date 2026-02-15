# CGA6444VF (Firmware 19.3B80-3.5.13) Authentication Implementation

## Hardware & Firmware
- **Model:** Arris CGA6444VF
- **Firmware:** 19.3B80-3.5.13
- **ISP:** Vodafone Deutschland (ex-Unitymedia/Kabel Deutschland)
- **Web Interface:** http://192.168.0.1

## Problem
The current vodafone driver expects `currentSessionId` in the HTML response, but this firmware version uses a completely different API-based authentication flow with double PBKDF2 hashing.

## Authentication Flow

### Overview
The authentication uses a two-stage PBKDF2-HMAC-SHA256 hashing process:

1. Request salt values with special keyword `seeksalthash`
2. Compute first hash: `PBKDF2-SHA256(password, salt, 1000 iterations, 128 bits)`
3. Compute second hash: `PBKDF2-SHA256(hash1_hex_string, saltwebui, 1000 iterations, 128 bits)`
4. Send final hash with `logout=true` parameter to terminate existing sessions

### Step-by-Step Implementation

#### Step 1: Request Salt Values
```http
POST /api/v1/session/login HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Cookie: cwd=No

username=admin&password=seeksalthash
```

**Response:**
```json
{
  "error": "ok",
  "salt": "CJxnB3ROWZw",
  "saltwebui": "abc123def456"
}
```

**Important:** Save the `PHPSESSID` cookie from this response for subsequent requests.

#### Step 2: Compute Double PBKDF2 Hash

**Python Implementation:**
```python
import hashlib
from binascii import hexlify

def compute_vodafone_hash(password: str, salt: str, saltwebui: str) -> str:
    """
    Compute the double PBKDF2 hash used by Vodafone Station firmware 19.3B80-3.5.13
    
    Args:
        password: User password (plain text)
        salt: Salt value from API response
        saltwebui: SaltWebUI value from API response
        
    Returns:
        Final hash as hex string
    """
    # First hash: PBKDF2-HMAC-SHA256(password, salt)
    hash1 = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        1000,  # iterations
        16     # 128 bits = 16 bytes
    )
    hash1_hex = hexlify(hash1).decode('utf-8')
    
    # Second hash: PBKDF2-HMAC-SHA256(hash1_hex_string, saltwebui)
    # CRITICAL: Use hash1_hex as UTF-8 string, not as bytes!
    hash2 = hashlib.pbkdf2_hmac(
        'sha256',
        hash1_hex.encode('utf-8'),  # Convert hex string to bytes
        saltwebui.encode('utf-8'),
        1000,  # iterations
        16     # 128 bits = 16 bytes
    )
    hash2_hex = hexlify(hash2).decode('utf-8')
    
    return hash2_hex
```

#### Step 3: Authenticate with Final Hash

```http
POST /api/v1/session/login HTTP/1.1
Host: 192.168.0.1
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Cookie: cwd=No; PHPSESSID=<session_id_from_step1>

username=admin&password=<hash2_hex>&logout=true
```

**Success Response:**
```json
{
  "error": "ok",
  "message": "MSG_LOGIN_1",
  "data": {
    "intf": "Lan",
    "user": "admin",
    "uid": "1",
    "Dpd": "No",
    "remoteAddr": "192.168.0.13",
    "userAgent": "...",
    "httpReferer": null
  }
}
```

## Technical Details

### Required Headers
- `Content-Type: application/x-www-form-urlencoded; charset=UTF-8`
- `X-Requested-With: XMLHttpRequest`
- `Origin: http://192.168.0.1` (optional but recommended)
- `Referer: http://192.168.0.1/` (optional but recommended)

### Required Cookies
- `cwd=No` - Must be set before first request
- `PHPSESSID` - Session cookie from salt request

### Important Notes
1. **Session Management:** The `logout=true` parameter terminates any existing session. Without it, you get error `MSG_LOGIN_150` (user already logged in).
2. **Salt Validity:** Both `salt` and `saltwebui` must be used from the **same** salt request. They change with each request.
3. **PHPSESSID:** Must be preserved between salt request and login request.
4. **Hash Encoding:** The first hash must be converted to a hex string before being used as input to the second hash.

## Bash Reference Implementation

```bash
#!/bin/bash

MODEM_IP="192.168.0.1"
USERNAME="admin"
PASSWORD="your_password_here"
COOKIE_FILE=$(mktemp)

# Step 1: Get salts
SALT_RESPONSE=$(curl -s -c "$COOKIE_FILE" -b 'cwd=No' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  -H 'X-Requested-With: XMLHttpRequest' \
  --data "username=${USERNAME}&password=seeksalthash" \
  "http://${MODEM_IP}/api/v1/session/login")

SALT=$(echo "$SALT_RESPONSE" | grep -oP '"salt":"\K[^"]+')
SALTWEBUI=$(echo "$SALT_RESPONSE" | grep -oP '"saltwebui":"\K[^"]+')

# Step 2: Compute hash
FINAL_HASH=$(python3 -c "
import hashlib
from binascii import hexlify
hash1 = hashlib.pbkdf2_hmac('sha256', b'${PASSWORD}', b'${SALT}', 1000, 16)
hash2 = hashlib.pbkdf2_hmac('sha256', hexlify(hash1), b'${SALTWEBUI}', 1000, 16)
print(hexlify(hash2).decode())
")

# Step 3: Login
curl -s -b "$COOKIE_FILE" \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  -H 'X-Requested-With: XMLHttpRequest' \
  --data "username=${USERNAME}&password=${FINAL_HASH}&logout=true" \
  "http://${MODEM_IP}/api/v1/session/login"
```

## Error Messages

- `MSG_LOGIN_1` - Invalid credentials or hash computation error
- `MSG_LOGIN_150` - User already logged in (add `logout=true` parameter)
- `Unauthorized access` - Missing or invalid session cookie

## JavaScript Source Analysis

The authentication logic is implemented in `/js/login.js`:

```javascript
var hashed1 = doPbkdf2NotCoded($("#password").val(), distantsaltstored);
$.ajax({
    url: 'api/session/login',
    type: 'POST',
    data: {
        username: username,
        password: doPbkdf2NotCoded(hashed1, distantsaltstoredWebui)
    }
})
```

Function `doPbkdf2NotCoded`:
```javascript
function doPbkdf2NotCoded(passwd, saltLocal) {
    var derivedKey = sjcl.misc.pbkdf2(passwd, saltLocal, 1000, 128);
    var hexdevkey = sjcl.codec.hex.fromBits(derivedKey);
    return hexdevkey;
}
```

Uses Stanford JavaScript Crypto Library (SJCL) with HMAC-SHA256 (default).

## Testing

Tested successfully on:
- Firmware: 19.3B80-3.5.13
- Hardware: Arris CGA6444VF
- ISP: Vodafone Deutschland
- Date: February 2026

## Request for Integration

Would appreciate if this authentication method could be integrated into the vodafone driver. Happy to provide additional testing or information if needed.

## Credits

Reverse-engineered through JavaScript analysis and network traffic inspection.