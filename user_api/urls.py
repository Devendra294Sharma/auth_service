from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import SignUpView, LoginView, LogoutView, PermissionViewSet, RoleViewSet, RolePermissionsViewSet

router = DefaultRouter()
router.register(r'permissions', PermissionViewSet)
router.register(r'roles', RoleViewSet)
router.register(r'role-permissions', RolePermissionsViewSet, basename='role-permissions')

urlpatterns = [
    path('api/sign-up/', SignUpView.as_view(), name='sign-up'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/logout/', LogoutView.as_view(), name='logout'),
    path('api/', include(router.urls)),  
]

