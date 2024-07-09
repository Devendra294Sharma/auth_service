from rest_framework import serializers
from .models import User
from .models import Role, Permissions
from rest_framework.validators import UniqueValidator


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permissions
        fields = '__all__'
        read_only_fields = ['code']


class RoleSerializer(serializers.ModelSerializer):
    permissions = PermissionSerializer(many=True, read_only=True)

    class Meta:
        model = Role
        fields = ['uuid', 'name', 'permissions']
        

class UserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(validators=[UniqueValidator(queryset=User.objects.all())])
    roles = RoleSerializer(many=True, read_only=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'uuid', 'roles']
        extra_kwargs = {
            'password': {'write_only': True},
        }

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    

class RolePermissionsSerializer(serializers.ModelSerializer):
    uuid = serializers.UUIDField(required=True)
    permissions = serializers.PrimaryKeyRelatedField(queryset=Permissions.objects.all(), many=True)

    class Meta:
        model = Role
        fields = ['uuid', 'permissions']

    def update(self, instance, validated_data):
        permissions = validated_data.pop('permissions', None)
        if permissions is not None:
            instance.permissions.set(permissions)
        return super().update(instance, validated_data)

    def create(self, validated_data):
        role_uuid = validated_data['uuid']
        role = Role.objects.get(uuid=role_uuid)
        permissions = validated_data['permissions']
        role.permissions.set(permissions)
        return role


        


