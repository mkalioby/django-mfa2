import pytest

# @pytest.fixture
# def api_request(rf):
#     request = rf.get('/url')
#     # Modify the request object as needed (e.g., set user, add data)
#     return request

# @pytest.fixture
# def create_test_model(db):
#     def make_model(**kwargs):
#         return MyModel.objects.create(**kwargs)
#     return make_model

@pytest.fixture
def authenticated_user(client, django_user_model):
    user = django_user_model.objects.create_user(username='test', password='123')
    client.login(username='test', password='123')
    return user