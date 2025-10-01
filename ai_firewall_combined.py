
def detect_auth_brute_force(src_ip, dst_ip, dst_port):
    """Détecte les tentatives d'authentification répétées (force brute potentielle)."""
    now = datetime.now()
    
    # Ports standard pour FTP et SSH
    auth_ports = [21, 22, 2222]
    
    if dst_port not in auth_ports:
        return False
    
    # Enregistrer cette tentative
    auth_attempt_tracker[src_ip].append(now)
    
    # Nettoyer les anciens enregistrements (plus vieux que 60 secondes)
    while auth_attempt_tracker[src_ip] and (now - auth_attempt_tracker[src_ip][0]).total_seconds() > 60:
        auth_attempt_tracker[src_ip].pop(0)
    
    # Vérifier si le nombre de tentatives dépasse le seuil
    if len(auth_attempt_tracker[src_ip]) > AUTH_ATTEMPT_THRESHOLD:
HTTP_CONNECTION_THRESHOLD = 50  # Nombre de connexions HTTP par IP source par minute
HTTP_INCOMPLETE_THRESHOLD = 10  # Nombre de connexions HTTP incomplètes
        logger.warning(f"⚠️ Tentative de force brute potentielle détectée de {src_ip} ({len(auth_attempt_tracker[src_ip])} tentatives en 60s)")
        # Nettoyer le tracker pour cette IP
        auth_attempt_tracker[src_ip] = []
        return True
    
    return False

def detect_http_dos(src_ip, dst_ip, dst_port, packet):
    """Détecte les attaques DoS HTTP comme Slowloris, GoldenEye, et Hulk."""
    now = datetime.now()
    
    # Ne vérifier que pour les ports HTTP(S)
    if dst_port not in [80, 443, 8080, 8443]:
        return False, None
    
    # Enregistrer la connexion HTTP
    http_connection_tracker[src_ip].append(now)
    
    # Détecter les connexions incomplètes (Slowloris)
    if TCP in packet and Raw in packet:
        payload = str(packet[Raw].load)
        # Si c'est une demande HTTP incomplète
        if "HTTP/1." in payload and not "\r\n\r\n" in payload:
            http_incomplete_tracker[src_ip] += 1
    
    # Nettoyer les anciennes connexions
    while http_connection_tracker[src_ip] and (now - http_connection_tracker[src_ip][0]).total_seconds() > 60:
        http_connection_tracker[src_ip].pop(0)
    
    # Vérifier les seuils
    attack_type = None
    
    # Trop de connexions HTTP (possible GoldenEye/Hulk)
    if len(http_connection_tracker[src_ip]) > HTTP_CONNECTION_THRESHOLD:
        attack_type = "HTTP DoS (GoldenEye/Hulk)"
        logger.warning(f"⚠️ Attaque HTTP DoS potentielle détectée de {src_ip} ({len(http_connection_tracker[src_ip])} connexions en 60s)")
        http_connection_tracker[src_ip] = []
        
    # Trop de connexions incomplètes (possible Slowloris)
    elif http_incomplete_tracker[src_ip] > HTTP_INCOMPLETE_THRESHOLD:
        attack_type = "Slowloris Attack"
        logger.warning(f"⚠️ Attaque Slowloris potentielle détectée de {src_ip} ({http_incomplete_tracker[src_ip]} connexions incomplètes)")
        http_incomplete_tracker[src_ip] = 0
    
    return attack_type is not None, attack_type

# Modèles d'attaques web
SQL_INJECTION_PATTERNS = [
    "1=1", "OR 1=1", "' OR '1'='1", "UNION SELECT", "DROP TABLE",
    "INTO OUTFILE", "INFORMATION_SCHEMA", "sysobjects", "xp_cmdshell",
    "exec(", "EXEC("
]

XSS_PATTERNS = [
    "<script>", "</script>", "javascript:", "onerror=", "onload=",
    "eval(", "document.cookie", "alert(", "String.fromCharCode(",
    "<!--", "iframe", "onclick="
]

def detect_web_attacks(src_ip, dst_ip, dst_port, packet):
    """Détecte les attaques web comme l'injection SQL et XSS."""
    # Ne vérifier que pour les ports HTTP(S)
    if dst_port not in [80, 443, 8080, 8443]:
        return False, None
    
    # Vérifier seulement les paquets avec des données
    if Raw not in packet:
        return False, None
    
    # Extraire le contenu du paquet
    payload = str(packet[Raw].load)
    
    # Vérifier l'injection SQL
    for pattern in SQL_INJECTION_PATTERNS:
        if pattern.lower() in payload.lower():
            logger.warning(f"⚠️ Tentative d'injection SQL potentielle détectée de {src_ip}")
            return True, "SQL Injection"
    
    # Vérifier XSS
    for pattern in XSS_PATTERNS:
        if pattern.lower() in payload.lower():
            logger.warning(f"⚠️ Tentative de XSS potentielle détectée de {src_ip}")
            return True, "XSS Attack"
    
    return False, None
