from django.contrib import admin

from auth2.models import User


@admin.register(User)
class UserAdmin(admin.ModelAdmin):

    list_display = ('id', 'name', 'email', 'is_active')
    list_display_links = ('id', 'name')
    search_fields = ('name', 'email')
    list_filter = ('role', 'is_active')

# Register your models here.
