from fastapi import HTTPException

class ZentriqError(Exception):
    def __init__(self, message: str, status_code: int = 500):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

class AuthenticationError(ZentriqError):
    def __init__(self, message: str = "Invalid or missing API key"):
        super().__init__(message, status_code=401)

class EngineError(ZentriqError):
    def __init__(self, message: str = "Security engine error"):
        super().__init__(message, status_code=500)
