import time
import random
from datetime import datetime
from . import ActionResult

def add_security_group_rule(ip: str, port: int = 443, protocol: str = "tcp", simulate_fail: bool = False) -> ActionResult:
    """
    Mock boto3 Security Group rule add to block or allow traffic.
    """
    start_time = time.time()
    
    # Simulate network/AWS delay
    time.sleep(random.uniform(0.1, 0.3))
    
    status = "failed" if (simulate_fail or ip == "error") else "success"
    duration_ms = int((time.time() - start_time) * 1000)
    
    request_id = f"req-{random.randint(10000000, 99999999)}-{random.randint(1000, 9999)}"
    
    if status == "success":
        mock_boto3_response = {
            "ResponseMetadata": {
                "RequestId": request_id,
                "HTTPStatusCode": 200,
                "HTTPHeaders": {
                    "server": "AmazonEC2",
                    "content-type": "text/xml;charset=UTF-8",
                    "date": datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
                },
                "RetryAttempts": 0
            },
            "Return": True
        }
    else:
        mock_boto3_response = {
            "ResponseMetadata": {
                "RequestId": request_id,
                "HTTPStatusCode": 403,
                "HTTPHeaders": {
                    "server": "AmazonEC2",
                    "content-type": "text/xml;charset=UTF-8",
                    "date": datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
                },
                "RetryAttempts": 1
            },
            "Error": {
                "Code": "UnauthorizedOperation",
                "Message": "You are not authorized to perform this operation."
            }
        }
    
    return ActionResult(
        action="aws_block",
        target=f"{ip}:{port}/{protocol}",
        status=status,
        timestamp=datetime.utcnow().isoformat(),
        duration_ms=duration_ms,
        reversible=True,
        response_data=mock_boto3_response
    )
