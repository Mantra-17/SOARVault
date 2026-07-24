def calculate_risk_score(severity: str, abuse_score: int or None, vt_votes: str or int or None) -> int:
    """
    Calculates a composite risk score (0-100) based on severity, 
    AbuseIPDB reputation, and VirusTotal detections.
    """
    # 1. Base score from vendor severity
    severity_map = {
        "critical": 65,
        "high": 45,
        "medium": 25,
        "low": 10
    }
    score = severity_map.get(severity.lower(), 25)
    
    # 2. Add points from AbuseIPDB (up to 20 points)
    if abuse_score is not None:
        # Scale 0-100 to 0-20
        score += int(abuse_score * 0.2)
        
    # 3. Add points from VirusTotal (up to 25 points)
    if vt_votes is not None:
        malicious = 0
        total = 72 # default denominator
        
        if isinstance(vt_votes, str) and "/" in vt_votes:
            try:
                parts = vt_votes.split("/")
                malicious = int(parts[0])
                total = max(int(parts[1]), 1)
            except ValueError:
                pass
        elif isinstance(vt_votes, (int, float)):
            malicious = int(vt_votes)
            
        ratio = malicious / total if total > 0 else 0
        score += int(ratio * 25)
        
    # 4. Cap score between 0 and 100
    final_score = max(0, min(100, score))
    return final_score
