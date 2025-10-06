from rest_framework import status
from rest_framework.generics import GenericAPIView
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from django.utils.translation import gettext_lazy as _

from api.permissions import IsAuthenticated, IsClient, IsSeller, IsAdmin
from api.serializers import RegisterUserSerializer, ProfileSerializer, LoginSerializer, RefreshTokenSerializer
from auth2.models import User
from auth2.services import JwtAuthService


class RegisterApiView(GenericAPIView):

    serializer_class = RegisterUserSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.save()

        service = JwtAuthService()
        tokens = service.get_tokens(user)

        read_serializer = ProfileSerializer(user, context={'request': request})

        return Response({
            **read_serializer.data,
            **tokens,
        }, status.HTTP_201_CREATED)


class LoginApiView(GenericAPIView):

    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data.get('email')
        password = serializer.validated_data.get('password')

        user = User.objects.authenticate(email, password)

        if user is None:
            return Response({'detail': _('Не существует пользователя или неверный пароль')}, status.HTTP_401_UNAUTHORIZED)

        service = JwtAuthService()
        tokens = service.get_tokens(user)

        read_serializer = ProfileSerializer(user, context={'request': request})

        return Response({
            **read_serializer.data,
            **tokens,
        })


class ProfileApiView(GenericAPIView):

    serializer_class = ProfileSerializer
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        serializer = self.get_serializer(request.user2, context={'request': request})
        return Response(serializer.data)

    def patch(self, request, *args, **kwargs):
        serializer = self.get_serializer(request.user2, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return self.get(request, *args, **kwargs)


class RefreshTokenAPiView(GenericAPIView):
    serializer_class = RefreshTokenSerializer
    permission_classes = (AllowAny,)

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        r_token = serializer.validated_data.get('refresh_token')
        tokens = JwtAuthService.refresh_token(r_token)
        if tokens is None:
            return Response({'detail': 'Ваш refresh_token не верный или истек срок действия.'}, status.HTTP_400_BAD_REQUEST)

        return Response(tokens)


class DeleteAccountAPiView(GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def delete(self, request, *args, **kwargs):
        user = request.user2
        user.is_active = False
        user.save()
        return Response(status=status.HTTP_204_NO_CONTENT)


class EndpointForClientApiView(GenericAPIView):
    permission_classes = (IsAuthenticated, IsClient)

    def get(self, request, *args, **kwargs):
        return Response({'detail': 'Endpoint for the clients.'})


class EndpointForSellerApiView(GenericAPIView):
    permission_classes = (IsAuthenticated, IsSeller)

    def get(self, request, *args, **kwargs):
        return Response({'detail': 'Endpoint for the sellers.'})


class EndpointForAdminApiView(GenericAPIView):
    permission_classes = (IsAuthenticated, IsAdmin)

    def get(self, request, *args, **kwargs):
        return Response({'detail': 'Endpoint for the admins.'})

