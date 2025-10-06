from rest_framework import permissions, status
from rest_framework.exceptions import AuthenticationFailed

from api.exceptions import GenericAPIException
from auth2.models import User


class IsAuthenticated(permissions.BasePermission):

    def has_permission(self, request, view):
        if request.user2.is_authenticated:
            return True
        raise GenericAPIException(detail='Не авторизован.', status_code=status.HTTP_401_UNAUTHORIZED)


class IsAuthenticatedOrReadOnly(permissions.BasePermission):

    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True

        return request.user2.is_authenticated


class IsClient(permissions.BasePermission):

    def has_permission(self, request, view):
        return request.user2.role == User.CLIENT


class IsSeller(permissions.BasePermission):

    def has_permission(self, request, view):
        return request.user2.role == User.SELLER


class IsAdmin(permissions.BasePermission):

    def has_permission(self, request, view):
        return request.user2.role == User.ADMIN