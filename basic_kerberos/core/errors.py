class KerberosError(Exception):
    """Base class for Kerberos-related errors."""
    pass

class AuthenticationError(KerberosError):
    pass

class TicketError(KerberosError):
    pass

class ReplayError(KerberosError):
    pass
