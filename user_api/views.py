from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from .models import User
from rest_framework.views import APIView
from .models import Role, Permissions
from .serializers import RoleSerializer, UserSerializer, PermissionSerializer,RolePermissionsSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework import viewsets

class PermissionViewSet(viewsets.ModelViewSet):
    queryset = Permissions.objects.all()
    serializer_class = PermissionSerializer

class RoleViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RoleSerializer

class SignUpView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer, role_uuid=None):
        user = serializer.save()
        if role_uuid:
            role = Role.objects.get(uuid=role_uuid)
            user.roles.add(role)
        else:
            default_role, created = Role.objects.get_or_create(name='normal_user')
            user.roles.add(default_role)
        return user

    def create(self, request, *args, **kwargs):
        role_uuid = request.data.get('role_uuid')
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = self.perform_create(serializer, role_uuid=role_uuid)
        headers = self.get_success_headers(serializer.data)
        
        return Response({
            'username': user.username,
            'email': user.email,
            'uuid': str(user.uuid),
            'roles': RoleSerializer(user.roles.all(), many=True).data
        }, status=status.HTTP_201_CREATED, headers=headers)
    

class LoginView(generics.GenericAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        user = self.authenticate(email=email, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            permissions = user.roles.values_list('permissions__code', flat=True)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user_uuid': str(user.uuid),
                'permissions': list(set(permissions)),
            }, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Invalid Credentials'}, status=status.HTTP_401_UNAUTHORIZED)

    def authenticate(self, email, password):
        try:
            user = User.objects.get(email=email)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.data.get('refresh')
            if not refresh_token:
                return Response({"error": "Refresh token not provided"}, status=status.HTTP_400_BAD_REQUEST)
            refresh_token_obj = RefreshToken(refresh_token)
            refresh_token_obj.blacklist()
            return Response({"message": "User logged out successfully"}, status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class RolePermissionsViewSet(viewsets.ModelViewSet):
    queryset = Role.objects.all()
    serializer_class = RolePermissionsSerializer
    lookup_field = 'uuid'
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        role = serializer.save()
        return Response(serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        role_uuid = kwargs.get('uuid')
        try:
            role = Role.objects.get(uuid=role_uuid)
        except Role.DoesNotExist:
            return Response({"error": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

        serializer = self.get_serializer(role, data=request.data, partial=kwargs.get('partial', False))
        serializer.is_valid(raise_exception=True)
        role = serializer.save()
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        role_uuid = kwargs.get('uuid')
        try:
            role = Role.objects.get(uuid=role_uuid)
        except Role.DoesNotExist:
            return Response({"error": "Role not found"}, status=status.HTTP_404_NOT_FOUND)

        role.permissions.clear()
        return Response(status=status.HTTP_204_NO_CONTENT)