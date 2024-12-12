from django.shortcuts import render, redirect
from django.contrib.auth import update_session_auth_hash, authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm, PasswordChangeForm
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string

#LOGIN VIEW IS GIVEN BELOW :
def login_view(request):
    if request.method == 'POST':
        username_or_email = request.POST['username_or_email']
        password = request.POST['password']
        # Check if the input is an email
        if '@' in username_or_email:
            try:
                user_obj = User.objects.get(email=username_or_email)
                username = user_obj.username  # Retrieve the username from the email
            except User.DoesNotExist:
                username = None
        else:
            username = username_or_email
        user = authenticate(request, username=username, password=password)
        print(username_or_email)
        print(password)
        print(user)
        if user:
            login(request, user)
            return redirect('dashboard')
        return render(request, 'accounts/login.html', {'error': 'Invalid credentials'})
    return render(request, 'accounts/login.html')


#SIGNUP VIEW :
def signup_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password != confirm_password:
            return render(request, 'accounts/signup.html', {
                'error': 'Passwords do not match',
                'username': username,
                'email': email,
            })

        if User.objects.filter(username=username).exists():
            return render(request, 'accounts/signup.html', {
                'error': 'Username already exists',
                'email': email,
            })
        
        if User.objects.filter(email=email).exists():
            return render(request, 'accounts/signup.html', {
                'error': 'Email already exists',
                'username': username,
            })

        # Validate password and collect errors
        try:
            validate_password(password)
        except ValidationError as e:
            return render(request, 'accounts/signup.html', {
                'password_errors': e.messages,
                'username': username,
                'email': email,
            })

        # Create the user
        user = User.objects.create_user(username=username, email=email, password=password)
        return redirect('login')

    return render(request, 'accounts/signup.html')


#FORGOT PASSWORD VIEW :
def forgot_password_view(request):
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email']
            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                return render(request, 'accounts/forgot_password.html', {'error': 'No account found with this email.'})
            
            token = default_token_generator.make_token(user)
            uid = urlsafe_base64_encode(str(user.pk).encode('utf-8'))
            
            domain = get_current_site(request).domain
            reset_link = f"http://{domain}/reset/{uid}/{token}/"

            subject = "Password Reset Request"
            message = (
                f"Hello {user.username},\n\n"
                "You requested to reset your password. Please click the link below to reset your password:\n"
                f"{reset_link}\n\n"
                "If you did not request a password reset, you can ignore this email."
            )
            
            send_mail(subject, message, 'adityaarorasamplle@gmail.com', [email])
            
            return redirect('password_reset_done')
    else:
        form = PasswordResetForm()
    return render(request, 'accounts/forgot_password.html', {'form': form})


#CHANGE PASSWORD VIEW :
@login_required
def change_password_view(request):
    if request.method == 'POST':
        form = PasswordChangeForm(request.user, request.POST)
        if form.is_valid():
            user=form.save()
            update_session_auth_hash(request, user)
            return redirect('login')
    else:
        form = PasswordChangeForm(request.user,)
    return render(request, 'accounts/change_password.html', {'form': form})


#DASHBOARD VIEW :
@login_required
def dashboard_view(request):
    return render(request, 'accounts/dashboard.html', {'user': request.user})


#PROFILE VIEW :
@login_required
def profile_view(request):
    return render(request, 'accounts/profile.html', {'user': request.user})


#LOGOUT VIEW :
def logout_view(request):
    logout(request)
    return redirect('login')
