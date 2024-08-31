import random
import string
from rest_framework.views import APIView
from django.shortcuts import render
from rest_framework import generics,filters,status
from .serializers import SignUpSerializer,AccountActivationSerializer,PasswordResetSerializer,PasswordResetVerifySerializer,PasswordChangeSerializer,ProfileSerializer,ProfileChangeSerializer,LoginSerializer,KnowledgeBaseSerializer,PromptMgmtSerializer
from django.contrib.auth import get_user_model,login,logout
from .models  import KnowledgeBase,PromptMgmt,AccountActivation
from rest_framework.generics import GenericAPIView
from rest_framework.mixins import ListModelMixin,CreateModelMixin,RetrieveModelMixin,UpdateModelMixin,DestroyModelMixin
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.response import Response
from rest_framework.permissions import AllowAny,IsAuthenticated
from rest_framework.authtoken.models import Token


class Account(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ProfileSerializer
    def get(self, request, format=None):
        serializer = self.serializer_class(request.user)
        return Response(serializer.data)
    
class AccountChange(GenericAPIView):
    permission_classes = (IsAuthenticated,)
    serializer_class = ProfileChangeSerializer
    def post(self, request, format=None):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            user = request.user
            if 'first_name' in serializer.validated_data:
                user.first_name = serializer.validated_data['first_name']
            if 'last_name' in serializer.validated_data:
                user.last_name = serializer.validated_data['last_name']
            user.save()
            content = {'success':'User information changed.'}
            return Response(content, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class SignUpView(generics.CreateAPIView):
    serializer_class = SignUpSerializer
    permission_classes = [AllowAny]
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            # Check if the email is already registered
            if get_user_model().objects.filter(email=email).exists():
                return Response({'error': 'Email is already registered.'}, status=status.HTTP_400_BAD_REQUEST)
            # Save the user first
            user = serializer.save()
            # Create a token for the user
            Token.objects.create(user=user)
            # Create email confirmation
            email_confirmation = AccountActivation(user=user)
            confirmation_code = email_confirmation.create_confirmation()
            return Response({
                'success': 'User signed up successfully.',
                'message': 'Your Activation Code Is: {code}'.format(code=confirmation_code) #SHOW ACTIVATION CODE
                }, status=status.HTTP_200_OK) 
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class AccountActivationView(GenericAPIView):
    serializer_class = AccountActivationSerializer
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid():
            activation_code = serializer.validated_data.get('code')  
            email_confirmation = AccountActivation.objects.filter(activation_code=activation_code).first()
            if email_confirmation:
                if email_confirmation.verify_confirmation(activation_code):
                    return Response({'success': 'Account Activated. Proceed To Log in'}, status=status.HTTP_200_OK)
                else:
                    return Response({'error': 'Invalid confirmation code.'}, status=status.HTTP_400_BAD_REQUEST)
            else:
                return Response({'error': 'Invalid confirmation code.'}, status=status.HTTP_400_BAD_REQUEST)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
        
class UserList(generics.ListAPIView):
    User = get_user_model()
    queryset = User.objects.all()
    serializer_class = SignUpSerializer
    permission_classes = [AllowAny]
    
class LoginView(GenericAPIView):
    serializer_class = LoginSerializer
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            token, created = Token.objects.get_or_create(user=user)
            if user is not None and user.email_confirmed:
                login(request, user)
                response_data = {
                    'user_id': user.id,
                    'success': 'User authenticated.',
                }
                response = Response(response_data, status=status.HTTP_200_OK)
                response['Authorization'] = f'Token {token.key}'
                return response
            elif user is not None and not user.email_confirmed:
                return Response({'error': 'Email not confirmed. Please activate your account.'}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                return Response({'error': 'Invalid email or password.'}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        logout(request)
        return Response({'success': 'User logged out successfully.'}, status=status.HTTP_200_OK)
    
def generate_verification_code():
    return ''.join(random.choices(string.digits, k=6))

class PasswordResetView(GenericAPIView):
    serializer_class = PasswordResetSerializer
    def post(self, request, format=None):
        serializer = PasswordResetSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            try:
                user = get_user_model().objects.get(email=email)
            except get_user_model().DoesNotExist:
                return Response({'error': 'User with this email does not exist.'}, status=status.HTTP_400_BAD_REQUEST)
            code = generate_verification_code()
            user.email_verification_code = code
            user.save()
            return Response({
               'success': f'Verification code is: {code}'
                }, status=status.HTTP_200_OK)  
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetVerifyView(GenericAPIView):
    serializer_class = PasswordResetVerifySerializer
    def post(self, request, format=None):
        serializer = PasswordResetVerifySerializer(data=request.data)
        if serializer.is_valid():
            code = serializer.validated_data['code']
            new_password = serializer.validated_data['new_password']
            # Find the user with the provided verification code
            try:
                user = get_user_model().objects.get(email_verification_code=code)
            except get_user_model().DoesNotExist:
                return Response({'error': 'Invalid verification code.'}, status=status.HTTP_400_BAD_REQUEST)
            # Set the new password and clear the verification code
            user.set_password(new_password)
            user.email_verification_code = None
            user.save()
            return Response({'success': 'Password reset successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class PasswordChangeView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = PasswordChangeSerializer
    def post(self, request, format=None):
        serializer = PasswordChangeSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            old_password = serializer.validated_data['old_password']
            new_password = serializer.validated_data['new_password']
            # Check if the current password is correct
            if not user.check_password(old_password):
                return Response({'error': 'Current password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)
            # Set the new password and save the user
            user.set_password(new_password)
            user.save()
            # Optional: Invalidate existing authentication tokens if needed
            return Response({'success': 'Password changed successfully.'}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class KnowledgeBaseList(GenericAPIView, ListModelMixin):
    queryset= KnowledgeBase.objects.all()
    serializer_class= KnowledgeBaseSerializer
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
class KnowledgeBaseCreate(GenericAPIView,CreateModelMixin):
    parser_class = [MultiPartParser, FormParser]
    queryset = KnowledgeBase.objects.all()
    serializer_class = KnowledgeBaseSerializer
    def post(self,request,*args,  **kwargs):
        return self.create(request, *args, **kwargs)
    
class KnowledgeBaseUpdate(GenericAPIView,UpdateModelMixin):
    queryset = KnowledgeBase.objects.all()
    serializer_class = KnowledgeBaseSerializer
    def put(self,request, *args , **kwargs):
        return self.update(request, *args, **kwargs)
    
class KnowledgeBaseDestroy(GenericAPIView,DestroyModelMixin):
    queryset = KnowledgeBase.objects.all()
    serializer_class = KnowledgeBaseSerializer
    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)
    
class PromptList(GenericAPIView, ListModelMixin):
    queryset= PromptMgmt.objects.all()
    serializer_class= PromptMgmtSerializer
    def get(self, request, *args, **kwargs):
        return self.list(request, *args, **kwargs)
    
class PromptCreate(GenericAPIView,CreateModelMixin):
    parser_class = [MultiPartParser, FormParser]
    queryset = PromptMgmt.objects.all()
    serializer_class = PromptMgmtSerializer
    def post(self,request,*args,  **kwargs):
        return self.create(request, *args, **kwargs)
    
class PromptUpdate(GenericAPIView,UpdateModelMixin):
    queryset = PromptMgmt.objects.all()
    serializer_class = PromptMgmtSerializer
    def put(self,request, *args , **kwargs):
        return self.update(request, *args, **kwargs)
    
class PromptDestroy(GenericAPIView,DestroyModelMixin):
    queryset = PromptMgmt.objects.all()
    serializer_class = PromptMgmtSerializer
    def delete(self, request, *args, **kwargs):
        return self.destroy(request, *args, **kwargs)


