from django.shortcuts import render

# Create your views here.
from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.shortcuts import render

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required

import logging
logger = logging.getLogger(__name__)

# MAIN PAGE
@login_required(login_url='/app/login')
def index(request):
    logger.error('index')
    return render(request, 'app/index.html')

# LOGIN PAGE
def login_view(request):
    # if request.user.is_authenticated():
    key = request.session.get('SoCkey')
    if key:
        return HttpResponseRedirect(reverse('app:index'))

    try:
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)

        if user is not None:
            new_token = Token.objects.create(user=user)
            new_token.save()
            request.session['SoCkey']=new_token.key
            request.session.set_expiry(300)
            login(request, user)
            return HttpResponseRedirect(reverse('app:index'))
        else:
            return render(request, 'app/login.html', {'message': 'Invalid Credential'})
    except:
        return render(request, 'app/login.html', {'message': ''})

# LOGOUT PAGE
@login_required(login_url='/app/login')
def logout_view(request):
    logout(request)
    request.session.clear()
    return HttpResponseRedirect(reverse('app:login'))

# REST TEST
from django.http import JsonResponse
@login_required(login_url='/app/login')
def json_test(request):
    return JsonResponse({'foo': 'bar'})