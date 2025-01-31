from django.shortcuts import get_object_or_404
from rest_framework.generics import GenericAPIView, RetrieveAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.response import Response
from rest_framework import status
from rest_framework.exceptions import PermissionDenied, ValidationError
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from .serializers import (
    EmailVerificationSerializer,
    PasswordResetRequestSerializer,
    SetNewPasswordSerializer,
    UserRegistrationSerializer,
    UserLoginSerializer,
    CustomUserSerializer,ChangePasswordSerializer, ChangeUsernameSerializer
)
from .models import CustomUser, PasswordResetToken
from datetime import timedelta
from django.utils import timezone
import uuid
import os
from dotenv import load_dotenv
from google.oauth2 import id_token
from google.auth.transport import requests
import time

load_dotenv()

class UserRegistrationAPIView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()

            # Send verification email
            verification_link = f"{os.getenv('FRONTEND_URL')}verify/{user.email_verification_token}/"
            send_mail(
                'Verify your email',
                f'Please click the following link to verify your email and activate your account: {verification_link}',
                settings.DEFAULT_FROM_EMAIL,
                [user.email],
                fail_silently=False,
            )

            return Response({"success": "User registered. Please check your email to verify your account."}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class EmailVerificationAPIView(APIView):
    permission_classes = [AllowAny]
    
    def get(self, request, token):
        return self._verify_email(token)
    
    def post(self, request, token):
        return self._verify_email(token)
    
    def _verify_email(self, token):
        try:
            user = CustomUser.objects.get(email_verification_token=token)
            
            if not user.is_verification_token_valid():
                return Response(
                    {"error": "Verification link has expired. Please request a new one."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if user.is_email_verified:
                return Response(
                    {"message": "Email is already verified."},
                    status=status.HTTP_200_OK,
                )

            # Update verification status but keep the token
            user.is_email_verified = True
            user.is_active = True
            user.save(update_fields=['is_email_verified', 'is_active'])

            return Response(
                {"message": "Email verified successfully."},
                status=status.HTTP_200_OK,
            )

        except CustomUser.DoesNotExist:
            return Response(
                {"error": "Invalid verification token."},
                status=status.HTTP_404_NOT_FOUND,
            )
        except Exception as e:
            return Response(
                {"error": "An error occurred during verification."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

class UserLoginAPIView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data
            refresh = RefreshToken.for_user(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
            }, status=status.HTTP_200_OK)
        except ValidationError as e:
            error_details = e.detail
            if isinstance(error_details, dict) and 'non_field_errors' in error_details:
                error_message = error_details['non_field_errors'][0]
            else:
                error_message = str(error_details)
            return Response({'error': error_message}, status=status.HTTP_400_BAD_REQUEST)

class UserLogoutAPIView(GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def post(self, request, *args, **kwargs):
        return self._handle_logout(request)

    def get(self, request, *args, **kwargs):
        return self._handle_logout(request)

    def _handle_logout(self, request):
        try:
            # Check both request.data and query parameters for refresh token
            refresh_token = request.data.get("refresh") if hasattr(request, 'data') else None
            if not refresh_token:
                refresh_token = request.GET.get("refresh")
            
            if not refresh_token:
                return Response({"error": "Refresh token is required"}, status=status.HTTP_400_BAD_REQUEST)

            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class UserInfoAPIView(RetrieveAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = CustomUserSerializer

    def get_object(self):
        user = self.request.user
        if user.role != 'userPortfolio':
            raise PermissionDenied({"error": "Access denied"})
        return user

class RequestPasswordResetEmail(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = CustomUser.objects.get(email=email)
                
                # Delete any existing tokens for this user
                PasswordResetToken.objects.filter(user=user).delete()
                
                # Create a new token
                expiration_time = timezone.now() + timedelta(hours=1)
                reset_token = PasswordResetToken.objects.create(
                    user=user,
                    token=uuid.uuid4(),
                    expires_at=expiration_time
                )
                
                # Fix the URL path
                reset_url = f"{os.getenv('FRONTEND_URL')}reset-password/{reset_token.token}"
                
                send_mail(
                    'Reset your password',
                    f'Use this link to reset your password: {reset_url}\nThis link will expire in 1 hour.',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )
                
                # Always return success to prevent email enumeration
                return Response(
                    {"success": "If an account exists with this email, you will receive reset instructions."}, 
                    status=status.HTTP_200_OK
                )
            except CustomUser.DoesNotExist:
                # Return the same message even if user doesn't exist (security best practice)
                return Response(
                    {"success": "If an account exists with this email, you will receive reset instructions."}, 
                    status=status.HTTP_200_OK
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SetNewPasswordAPIView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request, token):
        try:
            reset_token = PasswordResetToken.objects.get(token=token)
            if not reset_token.is_valid():
                return Response(
                    {"error": "Password reset link has expired."}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = SetNewPasswordSerializer(data=request.data)
            if serializer.is_valid():
                user = reset_token.user
                user.set_password(serializer.validated_data['password'])
                user.save()
                
                # Delete the used token
                reset_token.delete()
                
                return Response(
                    {"success": "Password has been reset successfully."}, 
                    status=status.HTTP_200_OK
                )
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
            
        except PasswordResetToken.DoesNotExist:
            return Response(
                {"error": "Invalid password reset token."}, 
                status=status.HTTP_404_NOT_FOUND
            )

class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if user.check_password(serializer.data.get('old_password')):
                user.set_password(serializer.data.get('new_password'))
                user.save()
                return Response({'message': 'Password changed successfully.'}, status=status.HTTP_200_OK)
            return Response({'error': 'Incorrect old password.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangeUsernameView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangeUsernameSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            if user.check_password(serializer.data.get('password')):
                new_username = serializer.data.get('new_username')
                if CustomUser.objects.filter(username=new_username).exists():
                    return Response({'error': 'This username is already taken.'}, status=status.HTTP_400_BAD_REQUEST)
                user.username = new_username
                user.save()
                return Response({'message': 'Username changed successfully.'}, status=status.HTTP_200_OK)
            return Response({'error': 'Incorrect password.'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class GoogleLoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            token = request.data.get('token')
            if not token:
                return Response(
                    {"error": "Token is required"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            try:
                # Verify the token
                idinfo = id_token.verify_oauth2_token(
                    token, 
                    requests.Request(), 
                    settings.GOOGLE_CLIENT_ID,
                    clock_skew_in_seconds=10  # Add some tolerance for clock skew
                )

                # Check if the token is expired
                if idinfo['exp'] < time.time():
                    return Response(
                        {"error": "Token has expired"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Verify issuer
                if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
                    return Response(
                        {"error": "Wrong issuer"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )

            except ValueError as e:
                print(f"Token verification error: {str(e)}")  # Debug log
                return Response(
                    {"error": f"Invalid token: {str(e)}"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Get user info from the token
            email = idinfo.get('email')
            if not email:
                return Response(
                    {"error": "Email not found in token"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

            name = idinfo.get('name', '')
            
            # Check if user exists
            try:
                user = CustomUser.objects.get(email=email)
            except CustomUser.DoesNotExist:
                # Create new user
                username = email.split('@')[0]
                base_username = username
                counter = 1
                
                # Ensure unique username
                while CustomUser.objects.filter(username=username).exists():
                    username = f"{base_username}{counter}"
                    counter += 1

                try:
                    user = CustomUser.objects.create_user(
                        email=email,
                        username=username,
                        is_email_verified=True,  # Google emails are verified
                        is_active=True
                    )
                except Exception as e:
                    print(f"User creation error: {str(e)}")  # Debug log
                    return Response(
                        {"error": "Failed to create user"}, 
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Generate tokens
            try:
                refresh = RefreshToken.for_user(user)
                
                return Response({
                    'access': str(refresh.access_token),
                    'refresh': str(refresh),
                    'user': {
                        'email': user.email,
                        'username': user.username
                    }
                }, status=status.HTTP_200_OK)
            except Exception as e:
                print(f"Token generation error: {str(e)}")  # Debug log
                return Response(
                    {"error": "Failed to generate authentication tokens"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )

        except Exception as e:
            print(f"Google login error: {str(e)}")  # Debug log
            return Response(
                {"error": "Authentication failed"}, 
                status=status.HTTP_400_BAD_REQUEST
            )