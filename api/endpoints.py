from django.urls import path
from .yasg import urlpatterns as url_doc
from . import api

urlpatterns = [
    path('register/', api.RegisterApiView.as_view()),
    path('login/', api.LoginApiView.as_view()),
    path('refresh-token/', api.RefreshTokenAPiView.as_view()),
    path('profile/', api.ProfileApiView.as_view()),
    path('delete-account/', api.DeleteAccountAPiView.as_view()),

    path('endpoint-for-client/', api.EndpointForClientApiView.as_view()),
    path('endpoint-for-seller/', api.EndpointForSellerApiView.as_view()),
    path('endpoint-for-admin/', api.EndpointForAdminApiView.as_view()),
]

urlpatterns += url_doc