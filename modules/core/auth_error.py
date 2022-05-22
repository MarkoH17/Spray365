class AuthError:
    def __init__(
        self,
        timestamp: str,
        trace_id: str,
        correlation_id: str,
        message: str,
        code: int,
        raw_message=None,
    ):
        self.timestamp = timestamp
        self.trace_id = trace_id
        self.correlation_id = correlation_id
        self.message = message
        self.code = code
        self.raw_message = raw_message
