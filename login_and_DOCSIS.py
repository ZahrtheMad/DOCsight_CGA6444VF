#!/usr/bin/env python3
"""
Vodafone Station CGA6444VF Login Test Script
============================================
Dieses Script authentifiziert sich bei der Vodafone Station mittels
doppeltem PBKDF2-Hashing und speichert die Session für weitere API-Calls.

Firmware: 19.3B80-3.5.13
Hardware: Arris CGA6444VF
"""

import hashlib
import requests
from binascii import hexlify
import sys


def compute_pbkdf2_hash(password: bytes, salt: bytes, iterations: int = 1000, dklen: int = 16) -> str:
    """
    Berechnet PBKDF2-HMAC-SHA256 Hash.
    
    Args:
        password: Passwort als Bytes
        salt: Salt als Bytes
        iterations: Anzahl der Iterationen (Standard: 1000)
        dklen: Länge des abgeleiteten Schlüssels in Bytes (Standard: 16 = 128 bit)
    
    Returns:
        Hex-kodierter Hash als String
    """
    key = hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen)
    return hexlify(key).decode('utf-8')


def derive_challenge(password: str, salt: str, saltwebui: str) -> str:
    """
    Berechnet den finalen Authentication-Challenge mittels doppeltem PBKDF2.
    
    Das Modem verwendet zwei aufeinanderfolgende PBKDF2-Hashes:
    1. hash1 = PBKDF2-HMAC-SHA256(password, salt, 1000, 128 bit)
    2. hash2 = PBKDF2-HMAC-SHA256(hash1_hex_string, saltwebui, 1000, 128 bit)
    
    WICHTIG: hash1 wird als HEX-STRING (nicht als rohe Bytes!) verwendet!
    
    Args:
        password: Klartext-Passwort
        salt: Salt-Wert vom Modem
        saltwebui: SaltWebUI-Wert vom Modem
    
    Returns:
        Finaler Hash zum Senden als Passwort
    """
    # Erster Hash: PBKDF2(password, salt)
    hash1_hex = compute_pbkdf2_hash(
        password.encode('utf-8'),
        salt.encode('utf-8')
    )
    
    # Zweiter Hash: PBKDF2(hash1_hex_string, saltwebui)
    # KRITISCH: hash1_hex als UTF-8 String kodieren, nicht als rohe Bytes!
    hash2_hex = compute_pbkdf2_hash(
        hash1_hex.encode('utf-8'),
        saltwebui.encode('utf-8')
    )
    
    return hash2_hex


def login_vodafone_station(host: str, username: str, password: str, timeout: int = 10) -> requests.Session:
    """
    Authentifiziert sich bei der Vodafone Station und gibt eine Session zurück.
    
    Args:
        host: Modem IP-Adresse (z.B. "192.168.0.1")
        username: Admin-Username (meist "admin")
        password: Admin-Passwort
        timeout: Request-Timeout in Sekunden
    
    Returns:
        Authenticated requests.Session object
    
    Raises:
        RuntimeError: Wenn Login fehlschlägt
    """
    base_url = f"http://{host}"
    
    # Erstelle neue Session
    session = requests.Session()
    
    # Setze Standard-Headers für ALLE Requests
    # Diese werden automatisch bei jedem Request mitgesendet
    session.headers.update({
        'User-Agent': 'Mozilla/5.0',
        'X-Requested-With': 'XMLHttpRequest',
        'Referer': f'{base_url}/',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
    })
    
    # Setze cwd Cookie (vom Modem erwartet)
    session.cookies.set('cwd', 'No', domain=host)
    
    print("=" * 60)
    print("Vodafone Station CGA6444VF Login")
    print("=" * 60)
    print()
    
    # ========================================================================
    # SCHRITT 1: Salt-Werte anfordern
    # ========================================================================
    print("1. Requesting salt values...")
    
    try:
        response = session.post(
            f"{base_url}/api/v1/session/login",
            data={
                'username': username,
                'password': 'seeksalthash',  # Spezielles Keyword für Salt-Request
                'logout': 'true'              # Beende evtl. aktive Sessions
            },
            timeout=timeout
        )
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Salt request failed: {e}")
    
    # Prüfe Response
    if data.get('error') != 'ok':
        raise RuntimeError(f"Salt request returned error: {data}")
    
    salt = data.get('salt')
    saltwebui = data.get('saltwebui')
    
    if not salt or not saltwebui:
        raise RuntimeError(f"Missing salt values in response: {data}")
    
    print(f"   Salt:       {salt}")
    print(f"   SaltWebUI:  {saltwebui}")
    print()
    
    # ========================================================================
    # SCHRITT 2: Doppelten PBKDF2-Hash berechnen
    # ========================================================================
    print("2. Computing double PBKDF2 hash...")
    
    challenge = derive_challenge(password, salt, saltwebui)
    print(f"   Final hash: {challenge}")
    print()
    
    # ========================================================================
    # SCHRITT 3: Login mit berechnetem Hash
    # ========================================================================
    print("3. Authenticating...")
    
    try:
        response = session.post(
            f"{base_url}/api/v1/session/login",
            data={
                'username': username,
                'password': challenge,  # Sende den berechneten Hash
                'logout': 'true'        # Beende alte Sessions
            },
            timeout=timeout
        )
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Login request failed: {e}")
    
    # Prüfe Erfolg
    if data.get('error') != 'ok':
        raise RuntimeError(f"Login failed: {data}")
    
    print("   ✅ LOGIN SUCCESSFUL!")
    
    # ========================================================================
    # SCHRITT 4: Session-Menu initialisieren (vom Original-Script)
    # ========================================================================
    # Das Original-Script macht nach dem Login noch einen Menu-Request
    # um die Session vollständig zu initialisieren
    print("4. Initializing session menu...")
    
    try:
        response = session.get(
            f"{base_url}/api/v1/session/menu",
            timeout=timeout
        )
        response.raise_for_status()
        data = response.json()
        
        if data.get('error') != 'ok':
            print(f"   ⚠️  Menu init warning: {data}")
        else:
            print("   ✓ Session menu initialized")
    except Exception as e:
        print(f"   ⚠️  Menu init failed (non-critical): {e}")
    
    print()
    
    # Der Login-Response setzt einen NEUEN Cookie - dieser wird automatisch
    # von requests.Session übernommen und für weitere Requests verwendet
    print("   Session is ready for authenticated requests.")
    print(f"   Cookie: PHPSESSID={session.cookies.get('PHPSESSID')}")
    print()
    
    # WICHTIG: Warte kurz, damit die Session aktiviert wird
    import time
    time.sleep(0.5)
    
    return session


def main():
    """Hauptfunktion für Standalone-Nutzung."""
    
    # Konfiguration
    MODEM_IP = "192.168.0.1"
    USERNAME = "admin"
    PASSWORD = "DEIN_PASSWORT_HIER"  # <-- ANPASSEN!
    
    # Prüfe ob Passwort gesetzt wurde
    if PASSWORD == "DEIN_PASSWORT_HIER":
        print("ERROR: Please set your password in the script!")
        sys.exit(1)
    
    try:
        # Login durchführen
        session = login_vodafone_station(MODEM_IP, USERNAME, PASSWORD)
        
        # Beispiel: DOCSIS-Status abrufen
        print("Example: Fetching DOCSIS status...")
        import time
        timestamp = int(time.time() * 1000)
        
        # Debug: Zeige Cookie
        print(f"   Using cookie: {session.cookies.get_dict()}")
        
        response = session.get(
            f"http://{MODEM_IP}/api/v1/sta_docsis_status",
            params={'_': timestamp}  # Timestamp verhindert Caching
            # Headers werden automatisch von session.headers übernommen
        )
        
        print(f"   HTTP Status: {response.status_code}")
        print(f"   Response: {response.text[:200]}")  # Erste 200 Zeichen
        
        if response.status_code == 200:
            data = response.json()
            if data.get('error') == 'ok':
                docsis_data = data.get('data', {})
                print(f"   Status: {docsis_data.get('operational', 'Unknown')}")
                print(f"   Downstream Channels: {len(docsis_data.get('downstream', []))}")
                print(f"   Upstream Channels: {len(docsis_data.get('upstream', []))}")
            else:
                print(f"   ❌ API returned error: {data}")
        else:
            print(f"   ❌ HTTP {response.status_code}")
        
        print()
        print("=" * 60)
        print("Session can now be used for further API calls.")
        print("=" * 60)
        
    except RuntimeError as e:
        print(f"\n❌ ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()