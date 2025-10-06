from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext_lazy as _
from rest_framework import serializers

from auth2.models import User


class ProfileSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ('id', 'email', 'name', 'role')
        extra_fields = {
            'id': {'read_only': True},
            # 'role': {'read_only': True},
        }


class RegisterUserSerializer(serializers.ModelSerializer):

    password1 = serializers.CharField(validators=[validate_password])
    password2 = serializers.CharField()

    class Meta:
        model = User
        fields = [
            'email',
            'name',
            'password1',
            'password2',
        ]

    def validate(self, attrs):
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')

        if password1 != password2:
            raise serializers.ValidationError({'password2': [_('Пароли не совпадают.')]})

        return attrs

    def create(self, validated_data):
        validated_data.pop('password1')
        validated_data['password'] = validated_data.pop('password2')

        return User.objects.create_user(**validated_data)


class LoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField()


class RefreshTokenSerializer(serializers.Serializer):
    refresh_token = serializers.CharField()