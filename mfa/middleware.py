import time
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.conf import settings
def process(request):
    next_check=request.session.get('mfa',{}).get("next_check",False)
    if not next_check: return None
    now=int(time.time())
    if now >= next_check:
        method=request.session["mfa"]["method"]
        path = request.META["PATH_INFO"]
        return HttpResponseRedirect(reverse(method+"_auth")+"?next=%s"%(settings.BASE_URL + path).replace("//", "/"))
    return None