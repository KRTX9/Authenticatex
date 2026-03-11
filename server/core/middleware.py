"""
Security middleware for enterprise-grade HTTP headers.
"""
from django.conf import settings


class SecurityHeadersMiddleware:
    """Adds Content-Security-Policy and Permissions-Policy headers to all responses.
    
    CSP prevents XSS by restricting which sources the browser may load scripts,
    styles, images, and connections from.
    
    Permissions-Policy restricts access to powerful browser features (camera,
    microphone, geolocation, etc.) that this app doesn't need.
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Build CSP from settings or use a strict default
        self.csp = getattr(settings, 'CONTENT_SECURITY_POLICY', None)
        if not self.csp:
            allowed_origins = ' '.join(
                getattr(settings, 'CORS_ALLOWED_ORIGINS', [])
            )
            self.csp = (
                "default-src 'self'; "
                "script-src 'self' https://accounts.google.com https://apis.google.com; "
                "style-src 'self' 'unsafe-inline' https://accounts.google.com; "
                "img-src 'self' data: https://*.googleusercontent.com; "
                f"connect-src 'self' https://accounts.google.com {allowed_origins}; "
                "frame-src https://accounts.google.com; "
                "object-src 'none'; "
                "base-uri 'self'; "
                "form-action 'self'; "
                "frame-ancestors 'none'"
            )
        
        self.permissions_policy = getattr(
            settings, 'PERMISSIONS_POLICY',
            'camera=(), microphone=(), geolocation=(), payment=()'
        )
    
    def __call__(self, request):
        response = self.get_response(request)
        response['Content-Security-Policy'] = self.csp
        response['Permissions-Policy'] = self.permissions_policy
        return response
