from django.shortcuts import render
from django.contrib.auth.models import User, auth
from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect
from .models import Profile
from django.contrib.auth import logout
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.forms import AuthenticationForm

# Create your views here.
def index(request):
  # if request.user.is_authenticated:
  #     return redirect('dashboard')
  if request.method == "POST":
      username = request.POST['username']
      password = request.POST['password']
      
      user = auth.authenticate(username=username, password=password)
      
      request.session['username'] = username
      if user is not None:
        auth.login(request, user)
        return redirect('/dashboard')
      else:
        messages.info(request, "Credentials Invalid")
        return redirect('/')
  else:
    return render(request, 'signin.html')
  
  form = AuthenticationForm()
  
  # return render(
  #     request=request,
  #     template_name="users/login.html", 
  #     context={'form': form}
  #     )
def signup(request):
  if request.method == "POST":
    username = request.POST['username']
    email = request.POST['email']
    password = request.POST['password']
    password2 = request.POST['password2']
    
    if password == password2:
      if User.objects.filter(email=email).exists():
        messages.info(request, 'Email Taken')
        return redirect('signup')
      elif User.objects.filter(username=username).exists():
        messages.info(request, 'Username Taken')
        return redirect('signup')
      else:
        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()
        
        #Log user in and redirect to setting page
        
        user_model = User.objects.get(username=username)
        new_profile = Profile.objects.create(user=user_model, id_user=user_model.id)
        new_profile.save()
        return redirect('signup')
    else:
      messages.info(request, 'Password Not Matching')
      return redirect('signup')
  return render(request, 'signup.html')

def dashboard(request):
  user = getattr(request, "user", None)
  is_authenticated = getattr(user, "is_authenticated", True)
  if is_authenticated == True:
    return render(request, 'dashboard.html')
  return redirect('/')

@csrf_exempt
def logout_view(request):
  logout(request)
  messages.info(request, "Logged out successfully!")
  return redirect('/')