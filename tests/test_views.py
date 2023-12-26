import pytest
from django.urls import reverse

@pytest.mark.django_db
def test_index_unauthenticated(client):
    url = reverse("mfa_home")
    response = client.get(url)
    assert response is not None
    assert response.status_code == 302
    assert response.url=="/accounts/login/?next=/"


@pytest.mark.django_db
def test_index_authenticated(client, authenticated_user):
    url = reverse("mfa_home")
    response = client.get(url)
    assert response is not None
    assert response.status_code == 200
    assert isinstance(response.templates, list)
    assert len(response.templates) == 4
    for template in response.templates:
        assert template.name in ["modal.html", "base.html", "mfa_base.html", "MFA.html"]



