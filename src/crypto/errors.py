class CryptoUnavailableError(RuntimeError):
    """Raised when encryption keys are unavailable. Callers must fail closed, never fall back to plaintext."""
