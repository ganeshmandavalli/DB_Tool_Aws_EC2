
from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name='home'),  # Home page
    path('audit/', views.audit_database, name='audit_database'),  # Audit endpoint
    path('audit_database/', views.audit_database, name='audit_database'),
]

