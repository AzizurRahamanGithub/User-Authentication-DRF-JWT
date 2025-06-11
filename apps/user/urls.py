from django.urls import path
from .views import SignUpView,LogoutView, UserChangePasswordAPIView,UserProfileDetailAPIView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView, TokenVerifyView
from .views import PasswordResetRQAPIView, OTPVerifyAPIView, PasswordResetAPIView,UserProfileAPIView
from django.conf.urls.static import static
from django.conf import settings

urlpatterns = [
    path('signup/', SignUpView.as_view(), name='signup'),
    path('login/', TokenObtainPairView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('pass-reset/request/', PasswordResetRQAPIView.as_view(), name='password-reset-request'),
    path('pass-reset/otp-verify/', OTPVerifyAPIView.as_view(), name='password-reset-verify'),
    path('pass-reset/change-pass/', PasswordResetAPIView.as_view(), name='password-reset-change'),
    path('profile/', UserProfileAPIView.as_view(), name='user-profile'),
    path('user-profile/<int:id>/', UserProfileDetailAPIView.as_view()),
    path("change-password/<int:pk>/", UserChangePasswordAPIView.as_view(), name="change_password"),
    
]
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)