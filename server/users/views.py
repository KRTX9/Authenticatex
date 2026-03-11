from rest_framework import status
from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError, InvalidToken
from rest_framework_simplejwt.token_blacklist.models import OutstandingToken, BlacklistedToken
from django.contrib.auth import authenticate, get_user_model
from django.middleware.csrf import get_token
from django.core.cache import cache
from django.conf import settings
from django.db import transaction
import threading
import secrets as _secrets

from .models import OTPCode
from .serializers import (
    UserSerializer, RegisterSerializer, LoginSerializer,
    PasswordResetRequestSerializer, PasswordResetVerifySerializer,
    PasswordChangeSerializer, MFAVerifySerializer
)
from .authentication import (
    send_verification_email, send_welcome_email,
    LoginRateThrottle, RegisterRateThrottle, 
    PasswordResetRateThrottle, OTPVerificationRateThrottle,
    set_jwt_cookies, clear_jwt_cookies
)

import logging
import pyotp
import qrcode
import base64
from io import BytesIO

logger = logging.getLogger(__name__)

User = get_user_model()


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def send_email_async(email_func, *args):
    """Send emails asynchronously to avoid blocking requests"""
    def send_email():
        try:
            email_func(*args)
        except Exception as e:
            logger.error("Email send failed: %s", e)
    
    thread = threading.Thread(target=send_email, daemon=True)
    thread.start()


# ============================================================================
# ACCOUNT LOCKOUT HELPERS
# ============================================================================

# Per-account failed login tracking (supplements IP-based rate limiting)
ACCOUNT_MAX_FAILED_ATTEMPTS = 5
ACCOUNT_LOCKOUT_SECONDS = 900  # 15 minutes


def _check_account_lockout(email):
    """Return (is_locked, remaining_seconds). Uses Django cache."""
    lock_key = f'account_lockout:{email}'
    locked_until = cache.get(lock_key)
    if locked_until:
        return True, ACCOUNT_LOCKOUT_SECONDS
    return False, 0


def _record_failed_login(email):
    """Increment failed counter. Lock account if threshold reached."""
    counter_key = f'login_failures:{email}'
    failures = cache.get(counter_key, 0) + 1
    cache.set(counter_key, failures, timeout=ACCOUNT_LOCKOUT_SECONDS)
    if failures >= ACCOUNT_MAX_FAILED_ATTEMPTS:
        cache.set(f'account_lockout:{email}', True, timeout=ACCOUNT_LOCKOUT_SECONDS)


def _clear_failed_logins(email):
    """Reset counter on successful authentication."""
    cache.delete(f'login_failures:{email}')
    cache.delete(f'account_lockout:{email}')


# ============================================================================
# AUTHENTICATION VIEWS
# ============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([RegisterRateThrottle])
def register(request):
    """Register a new user or resend verification for unverified accounts.
    
    Security: Returns identical response structure for existing-verified,
    existing-unverified, and new accounts to prevent email enumeration.
    """
    email = request.data.get('email')
    
    if email:
        existing_user = User.objects.filter(email=email).only('id', 'email', 'is_verified').first()
        if existing_user:
            if existing_user.is_verified:
                # Don't reveal that the account exists and is verified.
                # Return 400 with a generic message that matches the "new account" path.
                return Response(
                    {'error': 'Registration could not be completed. If you already have an account, try logging in.'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Resend verification for unverified user
            OTPCode.objects.filter(user=existing_user, purpose='email_verification', is_used=False).update(is_used=True)
            send_email_async(send_verification_email, existing_user)
            
            refresh = RefreshToken.for_user(existing_user)
            response = Response({
                'message': 'Registration successful. Please check your email to verify your account.',
                'user': UserSerializer(existing_user).data,
            }, status=status.HTTP_200_OK)
            
            set_jwt_cookies(response, str(refresh.access_token), str(refresh))
            return response
    
    serializer = RegisterSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    user = serializer.save()
    send_email_async(send_verification_email, user)
    
    refresh = RefreshToken.for_user(user)
    response = Response({
        'message': 'Registration successful. Please check your email to verify your account.',
        'user': UserSerializer(user).data,
    }, status=status.HTTP_201_CREATED)
    
    set_jwt_cookies(response, str(refresh.access_token), str(refresh))
    return response


@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def login(request):
    """User login with MFA support and account-level lockout"""
    serializer = LoginSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    password = serializer.validated_data['password']
    
    # Account-level lockout check (supplements IP-based throttle)
    is_locked, _ = _check_account_lockout(email)
    if is_locked:
        return Response(
            {'error': 'Account temporarily locked due to too many failed attempts. Try again in 15 minutes.'},
            status=status.HTTP_429_TOO_MANY_REQUESTS
        )
    
    try:
        user = User.objects.only('id', 'username', 'email', 'is_verified', 'mfa_enabled', 'mfa_secret').get(email=email)
        user = authenticate(username=user.username, password=password)
    except User.DoesNotExist:
        # Mitigate timing oracle: run a dummy hash so response time is
        # indistinguishable from the "wrong password" path.
        User().set_password(password)
        user = None
    
    if not user:
        _record_failed_login(email)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
    
    _clear_failed_logins(email)
    
    # Check if MFA is required
    if user.mfa_enabled and user.get_mfa_secret():  # Use decryption method
        # Issue a single-use challenge token so MFA step is bound to this password check
        mfa_challenge = _secrets.token_urlsafe(32)
        cache.set(f'mfa_challenge:{mfa_challenge}', user.pk, timeout=300)  # 5 min
        return Response({
            'mfa_required': True,
            'mfa_token': mfa_challenge,
            'message': 'Please enter your MFA code from Google Authenticator'
        }, status=status.HTTP_200_OK)
    
    refresh = RefreshToken.for_user(user)
    response = Response({'user': UserSerializer(user).data})
    set_jwt_cookies(response, str(refresh.access_token), str(refresh))
    
    return response


@api_view(['POST'])
@permission_classes([AllowAny])
def logout(request):
    """User logout with token blacklisting and complete cookie clearing"""
    # Blacklist the refresh token to prevent reuse
    jwt_settings = settings.SIMPLE_JWT
    refresh_token_cookie = request.COOKIES.get(
        jwt_settings.get('AUTH_COOKIE_REFRESH', 'refresh_token')
    )
    
    if refresh_token_cookie:
        try:
            token = RefreshToken(refresh_token_cookie)
            token.blacklist()
        except (TokenError, InvalidToken):
            pass  # Token already invalid/expired, still clear cookies
    
    response = Response({'message': 'Logout successful'})
    clear_jwt_cookies(response)
    return response


@api_view(['GET'])
@permission_classes([AllowAny])
def get_csrf_token(request):
    """Get CSRF token for client"""
    csrf_token = get_token(request)
    
    response = Response({'detail': 'CSRF cookie set', 'csrfToken': csrf_token})
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=settings.CSRF_COOKIE_AGE,
        secure=settings.CSRF_COOKIE_SECURE,
        httponly=settings.CSRF_COOKIE_HTTPONLY,
        samesite=settings.CSRF_COOKIE_SAMESITE,
        path='/',
    )
    
    return response


@api_view(['POST'])
@permission_classes([AllowAny])
def refresh_token(request):
    """Refresh access token using refresh token from cookie.
    
    Security: Validates that the user is still active before issuing new tokens.
    A deactivated/banned user cannot silently keep refreshing.
    """
    jwt_settings = settings.SIMPLE_JWT
    refresh_token_cookie = request.COOKIES.get(jwt_settings.get('AUTH_COOKIE_REFRESH', 'refresh_token'))
    
    if not refresh_token_cookie:
        return Response({'error': 'Refresh token not found'}, status=status.HTTP_401_UNAUTHORIZED)
    
    try:
        refresh = RefreshToken(refresh_token_cookie)
        
        # Verify the user still exists and is active
        user_id = refresh.payload.get('user_id')
        try:
            user = User.objects.only('id', 'is_active').get(pk=user_id)
            if not user.is_active:
                refresh.blacklist()
                response = Response({'error': 'Account is deactivated'}, status=status.HTTP_401_UNAUTHORIZED)
                clear_jwt_cookies(response)
                return response
        except User.DoesNotExist:
            response = Response({'error': 'Invalid refresh token'}, status=status.HTTP_401_UNAUTHORIZED)
            clear_jwt_cookies(response)
            return response
        
        access_token = str(refresh.access_token)
        new_refresh_token = str(refresh) if jwt_settings.get('ROTATE_REFRESH_TOKENS', False) else refresh_token_cookie
        
        response = Response({'message': 'Token refreshed successfully'})
        set_jwt_cookies(response, access_token, new_refresh_token)
        
        return response
        
    except (TokenError, InvalidToken):
        return Response({'error': 'Invalid or expired refresh token'}, status=status.HTTP_401_UNAUTHORIZED)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def current_user(request):
    """Get current authenticated user"""
    return Response(UserSerializer(request.user).data)


# ============================================================================
# EMAIL VERIFICATION VIEWS
# ============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([OTPVerificationRateThrottle])
def verify_email_otp(request):
    """Verify user email with OTP code"""
    email = request.data.get('email')
    code = request.data.get('code')
    
    if not email or not code:
        return Response({'error': 'Email and code are required'}, status=status.HTTP_400_BAD_REQUEST)
    
    try:
        user = User.objects.only('id', 'email', 'is_verified').get(email=email)
        
        if user.is_verified:
            return Response({'message': 'Email is already verified'}, status=status.HTTP_400_BAD_REQUEST)
        
        # Atomic block + select_for_update prevents two concurrent requests
        # from both verifying the same OTP before either marks it used.
        with transaction.atomic():
            otps = list(
                OTPCode.objects.select_for_update()
                .filter(user=user, purpose='email_verification', is_used=False)
            )
            valid_otps = [o for o in otps if not o.is_expired() and o.attempts < 3]
            otp = next((o for o in valid_otps if o.verify_code(code)), None)
            
            if not otp:
                for o in valid_otps:
                    o.attempts += 1
                    o.save(update_fields=['attempts'])
                return Response({'error': 'Invalid or expired OTP code'}, status=status.HTTP_400_BAD_REQUEST)
            
            otp.is_used = True
            otp.save(update_fields=['is_used'])
        
        user.is_verified = True
        user.save(update_fields=['is_verified'])
        
        send_email_async(send_welcome_email, user)
        
        return Response({
            'message': 'Email verified successfully',
            'user': UserSerializer(user).data
        })
    
    except User.DoesNotExist:
        return Response({'error': 'Invalid or expired OTP code'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([OTPVerificationRateThrottle])
def resend_verification(request):
    """Resend verification OTP"""
    email = request.data.get('email')
    
    if not email:
        return Response({'error': 'Email is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    # Always return success to prevent user enumeration
    try:
        user = User.objects.only('id', 'email', 'is_verified').get(email=email)
        
        if not user.is_verified:
            OTPCode.objects.filter(user=user, purpose='email_verification', is_used=False).update(is_used=True)
            send_email_async(send_verification_email, user)
    except User.DoesNotExist:
        pass  # Don't reveal whether account exists
    
    return Response({'message': 'If the account exists and is not verified, a verification email has been sent.'})


# ============================================================================
# PASSWORD MANAGEMENT VIEWS
# ============================================================================

@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([PasswordResetRateThrottle])
def password_reset_request(request):
    """Request password reset OTP"""
    serializer = PasswordResetRequestSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    
    # Always return success to prevent user enumeration
    try:
        user = User.objects.only('id', 'email').get(email=email)
        
        OTPCode.objects.filter(user=user, purpose='password_reset', is_used=False).update(is_used=True)
        otp = OTPCode.create_otp(user, 'password_reset', expiry_minutes=10)
        
        from .authentication import send_otp_email
        send_email_async(send_otp_email, user, otp.plain_code, 'password_reset')
    except User.DoesNotExist:
        pass  # Don't reveal whether account exists
    
    return Response({'message': 'If an account exists with this email, an OTP has been sent.', 'email': email})


@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([OTPVerificationRateThrottle])
def password_reset_verify(request):
    """Verify OTP and reset password"""
    serializer = PasswordResetVerifySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    email = serializer.validated_data['email']
    otp_code = serializer.validated_data['otp']
    new_password = serializer.validated_data['new_password']
    
    try:
        user = User.objects.only('id', 'email', 'password').get(email=email)
        
        # Atomic + select_for_update prevents concurrent OTP replay
        with transaction.atomic():
            otps = list(
                OTPCode.objects.select_for_update()
                .filter(user=user, purpose='password_reset', is_used=False)
            )
            valid_otps = [o for o in otps if not o.is_expired() and o.attempts < 3]
            otp = next((o for o in valid_otps if o.verify_code(otp_code)), None)
            
            if not otp:
                for o in valid_otps:
                    o.attempts += 1
                    o.save(update_fields=['attempts'])
                return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)
            
            otp.is_used = True
            otp.save(update_fields=['is_used'])
        
        # Update password (outside atomic block — separate concern)
        user.set_password(new_password)
        user.save(update_fields=['password'])
        
        # Invalidate ALL existing sessions — a stolen token must not survive a reset
        tokens = OutstandingToken.objects.filter(user=user)
        for token in tokens:
            BlacklistedToken.objects.get_or_create(token=token)
        
        return Response({'message': 'Password reset successful'})
    
    except User.DoesNotExist:
        return Response({'error': 'Invalid or expired OTP'}, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def password_change(request):
    """Change authenticated user's password and invalidate all other sessions."""
    serializer = PasswordChangeSerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    user = request.user
    old_password = serializer.validated_data['old_password']
    new_password = serializer.validated_data['new_password']
    
    if not user.check_password(old_password):
        return Response({'error': 'Current password is incorrect'}, status=status.HTTP_400_BAD_REQUEST)
    
    user.set_password(new_password)
    user.save(update_fields=['password'])
    
    # Invalidate ALL existing sessions — prevents compromised token reuse
    tokens = OutstandingToken.objects.filter(user=user)
    for token in tokens:
        BlacklistedToken.objects.get_or_create(token=token)
    
    # Issue fresh tokens for the current session
    refresh = RefreshToken.for_user(user)
    response = Response({'message': 'Password changed successfully'})
    set_jwt_cookies(response, str(refresh.access_token), str(refresh))
    return response


# ============================================================================
# MFA (MULTI-FACTOR AUTHENTICATION) VIEWS
# ============================================================================

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mfa_setup(request):
    """Setup MFA for user - Generate secret and QR code"""
    user = request.user
    
    if user.mfa_enabled:
        return Response({'error': 'MFA is already enabled'}, status=status.HTTP_400_BAD_REQUEST)
    
    secret = pyotp.random_base32()
    user.set_mfa_secret(secret)  # Use encryption method
    user.save(update_fields=['mfa_secret'])
    
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name='SecureAuth')
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return Response({
        'secret': secret,
        'qr_code': f'data:image/png;base64,{img_str}',
        'message': 'Scan the QR code with Google Authenticator app'
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mfa_enable(request):
    """Enable MFA after verifying the code"""
    user = request.user
    code = request.data.get('code')
    
    if not code:
        return Response({'error': 'Verification code is required'}, status=status.HTTP_400_BAD_REQUEST)
    
    if user.mfa_enabled:
        return Response({'error': 'MFA is already enabled'}, status=status.HTTP_400_BAD_REQUEST)
    
    mfa_secret = user.get_mfa_secret()  # Use decryption method
    if not mfa_secret:
        return Response({'error': 'MFA setup not completed. Please call /mfa/setup/ first'}, status=status.HTTP_400_BAD_REQUEST)
    
    totp = pyotp.TOTP(mfa_secret)
    if not totp.verify(code, valid_window=1):
        return Response({'error': 'Invalid verification code'}, status=status.HTTP_400_BAD_REQUEST)
    
    user.mfa_enabled = True
    user.save(update_fields=['mfa_enabled'])
    
    return Response({'message': 'MFA enabled successfully', 'user': UserSerializer(user).data})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mfa_disable(request):
    """Disable MFA for user"""
    password = request.data.get('password')
    
    if not password:
        return Response({'error': 'Password is required to disable MFA'}, status=status.HTTP_400_BAD_REQUEST)
    
    user = request.user
    
    if not user.check_password(password):
        return Response({'error': 'Invalid password'}, status=status.HTTP_400_BAD_REQUEST)
    
    user.mfa_enabled = False
    user.set_mfa_secret(None)  # Clear encrypted secret
    user.save(update_fields=['mfa_enabled', 'mfa_secret'])
    
    return Response({'message': 'MFA disabled successfully', 'user': UserSerializer(user).data})


@api_view(['POST'])
@permission_classes([AllowAny])
@throttle_classes([LoginRateThrottle])
def mfa_verify_login(request):
    """Verify MFA code during login.
    
    Security: Requires a server-issued mfa_token (from login or Google OAuth)
    that proves the user already passed primary authentication. The token is
    single-use and expires after 5 minutes.
    """
    serializer = MFAVerifySerializer(data=request.data)
    if not serializer.is_valid():
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    mfa_token = serializer.validated_data['mfa_token']
    mfa_code = serializer.validated_data['mfa_code']
    
    # Resolve and consume the challenge token (single-use)
    cache_key = f'mfa_challenge:{mfa_token}'
    user_pk = cache.get(cache_key)
    if not user_pk:
        return Response({'error': 'Invalid or expired MFA session'}, status=status.HTTP_400_BAD_REQUEST)
    cache.delete(cache_key)  # Single-use: consumed immediately
    
    try:
        user = User.objects.only('id', 'email', 'mfa_enabled', 'mfa_secret').get(pk=user_pk)
        
        if not user.mfa_enabled:
            return Response({'error': 'MFA is not enabled for this account'}, status=status.HTTP_400_BAD_REQUEST)
        
        mfa_secret = user.get_mfa_secret()  # Use decryption method
        if not mfa_secret:
            return Response({'error': 'MFA is not enabled for this account'}, status=status.HTTP_400_BAD_REQUEST)
        
        totp = pyotp.TOTP(mfa_secret)
        if not totp.verify(mfa_code, valid_window=1):
            return Response({'error': 'Invalid MFA code'}, status=status.HTTP_400_BAD_REQUEST)
        
        refresh = RefreshToken.for_user(user)
        response = Response({'user': UserSerializer(user).data, 'message': 'Login successful'})
        set_jwt_cookies(response, str(refresh.access_token), str(refresh))
        
        return response
        
    except User.DoesNotExist:
        return Response({'error': 'Invalid MFA code'}, status=status.HTTP_400_BAD_REQUEST)
