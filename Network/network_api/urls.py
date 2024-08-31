from django.urls import path
from . import views
from django.contrib import admin
urlpatterns = [
    
    #USER LIST
    path('', views.Account.as_view(), name = 'accounts'),
    path('edit-details/', views.AccountChange.as_view(), name='edit-details'),
    path('login/', views.LoginView.as_view(),name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('signup/', views.SignUpView.as_view(), name='signup'),
    path('activate-account/', views.AccountActivationView.as_view(), name='account-activation'),
    path('password-change/', views.PasswordChangeView.as_view(), name='password-change'),
    path('password-reset/', views.PasswordResetView.as_view(), name='password-reset'),
    path('password-reset/verify/', views.PasswordResetVerifyView.as_view(), name='password-reset-verify'),
    path('userapigen/', views.UserList.as_view()),

    #USER REGISTRATION AND LOGIN URL's ON MAIN ADMIN URL FILE


    #KnowledgebaseURL's
    path('knowledgebaseapigen/', views.KnowledgeBaseList.as_view()), #VIEW Knowledgebase
    path('knowledgebaseapigenCreate/', views.KnowledgeBaseCreate.as_view()), #CREATE Knowledgebase
    path('knowledgebaseapigenUpd/<int:pk>', views.KnowledgeBaseUpdate.as_view()), #UPDATE Knowledgebase
    path('knowledgebaseapigenDel/<int:pk>', views.KnowledgeBaseDestroy.as_view()), #DELETE Knowledgebase

    #PromptMgmtURL's
    path('promptapigen/', views.PromptList.as_view()), #VIEW Prompt
    path('promptapigenCreate/', views.PromptCreate.as_view()), #CREATE Prompt
    path('promptapigenUpd/<int:pk>', views.PromptUpdate.as_view()), #UPDATE Prompt
    path('promptapigenDel/<int:pk>', views.PromptDestroy.as_view()), #DELETE Prompt

]
