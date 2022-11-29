from django.shortcuts import render
from django.contrib.auth.models import User, auth
from django.contrib import messages
from django.http import HttpResponse
from django.shortcuts import redirect
from .models import Profile

# Create your views here.
def index(request):
  return render(request, 'signin.html')
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
        return redirecet('signup')
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
