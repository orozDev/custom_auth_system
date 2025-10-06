from django.db import models
from django.utils.translation import gettext_lazy as _
import hashlib


class AnonymousUser:
    id = None
    pk = None
    email = ''
    is_active = False

    def __str__(self):
        return 'AnonymousUser'

    def __eq__(self, other):
        return isinstance(other, self.__class__)

    def __hash__(self):
        return 1

    def __int__(self):
        raise TypeError(
            'Cannot cast AnonymousUser to int. Are you trying to use it in place of '
            'User?'
        )

    def save(self):
        raise NotImplementedError(
            'Django doesn\'t provide a DB representation for AnonymousUser.'
        )

    def delete(self):
        raise NotImplementedError(
            'Django doesn\t provide a DB representation for AnonymousUser.'
        )

    def set_password(self, raw_password):
        raise NotImplementedError(
            'Django doesn\'t provide a DB representation for AnonymousUser.'
        )

    def check_password(self, raw_password):
        raise NotImplementedError(
            'Django doesn\'t provide a DB representation for AnonymousUser.'
        )

    @property
    def is_anonymous(self):
        return True

    @property
    def is_authenticated(self):
        return False


def make_password(password):
    if not isinstance(password, (bytes, str)):
        raise TypeError(
            'Password must be a string or bytes, got %s.' % type(password).__qualname__
        )
    return hashlib.sha256(password.encode()).hexdigest()


class UserManager(models.Manager):

    def authenticate(self, email, password):
        user = self.model.objects.filter(email=email).first()

        if user is None:
            return None

        if not user.is_active:
            return None

        if not user.check_password(password):
            return None

        return user

    def _create_user(self, email, password, **extra_fields):
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save()
        return user

    def create_user(self, email, password, **extra_fields):
        extra_fields.setdefault('role', User.CLIENT)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('role', User.ADMIN)

        if extra_fields.get('role') is not True:
            raise ValueError(_('Роль должен быть администратором.'))

        return self._create_user(email, password, **extra_fields)


class User(models.Model):

    ADMIN = 'admin'
    CLIENT = 'client'
    SELLER = 'seller'

    ROLES = (
        (ADMIN, _('Админ')),
        (CLIENT, _('Клиент')),
        (SELLER, _('Продавец'))
    )

    class Meta:
        verbose_name = _('пользователь')
        verbose_name_plural = _('пользователи')

    email = models.EmailField(_('почта'), unique=True)
    password = models.CharField(_('пароль'), max_length=128)
    name = models.CharField(_('ФИО'), max_length=100)
    role = models.CharField(_('роль'), max_length=20, choices=ROLES, default=CLIENT)
    is_active = models.BooleanField(_('активный'), default=True)
    date_joined = models.DateTimeField(_('дата регистрации'), auto_now_add=True)

    objects = UserManager()

    def __str__(self):
        return f'{self.email} - {self.name}'

    def set_password(self, password):
        self.password = make_password(password)

    def check_password(self, password: str):
        return bool(hashlib.sha256(password.encode()).hexdigest() == self.password)

    @property
    def is_authenticated(self):
        return True

# Create your models here.
