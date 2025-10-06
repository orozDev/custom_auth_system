from django.utils.deprecation import MiddlewareMixin

from auth2.services import JwtAuthService


class AuthenticationMiddleware(MiddlewareMixin):

    def process_request(self, request):
        request.user2 = JwtAuthService.get_user(request.META.get('HTTP_AUTHORIZATION'))
