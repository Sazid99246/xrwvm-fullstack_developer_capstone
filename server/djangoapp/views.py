from django.http import JsonResponse
from django.contrib.auth.models import User
from django.contrib.auth import login, logout, authenticate
from django.views.decorators.csrf import csrf_exempt
import json
import logging
import os
import requests

from .populate import initiate
from .models import CarMake, CarModel
from .restapis import get_request, post_review

# Logger
logger = logging.getLogger(__name__)

# Environment variables
sentiment_analyzer_url = os.environ.get("sentiment_analyzer_url", "")


# -------------------------
# Authentication Views
# -------------------------

@csrf_exempt
def login_user(request):
    """Handle user login"""
    data = json.loads(request.body)
    username = data['userName']
    password = data['password']

    user = authenticate(username=username, password=password)
    if user is not None:
        login(request, user)
        return JsonResponse({"userName": username, "status": "Authenticated"})
    return JsonResponse({"userName": username})


def logout_request(request):
    """Handle user logout"""
    logout(request)
    return JsonResponse({"userName": ""})


@csrf_exempt
def registration(request):
    """Handle user registration"""
    if request.method != "POST":
        return JsonResponse({"error": "POST request required"}, status=400)

    try:
        data = json.loads(request.body)
        username = data.get('userName')
        password = data.get('password')
        first_name = data.get('firstName', '')
        last_name = data.get('lastName', '')
        email = data.get('email', '')

        if not username or not password:
            return JsonResponse({"error": "Username and password are required"}, status=400)

        if User.objects.filter(username=username).exists():
            return JsonResponse({"userName": username, "error": "Already Registered"}, status=400)

        user = User.objects.create_user(
            username=username,
            password=password,
            first_name=first_name,
            last_name=last_name,
            email=email
        )

        login(request, user)
        return JsonResponse({"userName": username, "status": "Authenticated"})

    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON"}, status=400)
    except Exception as e:
        logger.exception("Error during registration")
        return JsonResponse({"error": str(e)}, status=500)


# -------------------------
# Cars Views
# -------------------------

def get_cars(request):
    """Return list of cars"""
    if CarMake.objects.count() == 0:
        initiate()

    car_models = CarModel.objects.select_related('car_make')
    cars = [{"CarModel": cm.name, "CarMake": cm.car_make.name} for cm in car_models]
    return JsonResponse({"CarModels": cars})


# -------------------------
# Sentiment Analysis
# -------------------------

def analyze_review_sentiments(text):
    """Call external sentiment analyzer"""
    if not sentiment_analyzer_url:
        logger.error("Sentiment analyzer URL not set")
        return {"sentiment": "unknown"}

    request_url = sentiment_analyzer_url + "analyze/" + text
    try:
        response = requests.get(request_url)
        return response.json()
    except Exception as err:
        logger.error(f"Error analyzing sentiment: {err}")
        return {"sentiment": "unknown"}


# -------------------------
# Dealership Views
# -------------------------

def get_dealerships(request, state="All"):
    """Fetch dealerships"""
    endpoint = "/fetchDealers" if state == "All" else f"/fetchDealers/{state}"
    dealerships = get_request(endpoint)
    return JsonResponse({"status": 200, "dealers": dealerships})


def get_dealer_reviews(request, dealer_id):
    """Fetch reviews for a dealer"""
    if dealer_id:
        endpoint = f"/fetchReviews/dealer/{dealer_id}"
        reviews = get_request(endpoint)
        for review_detail in reviews:
            sentiment_response = analyze_review_sentiments(review_detail.get('review', ''))
            review_detail['sentiment'] = sentiment_response.get('sentiment', 'unknown')
        return JsonResponse({"status": 200, "reviews": reviews})
    return JsonResponse({"status": 400, "message": "Bad Request"})


def get_dealer_details(request, dealer_id):
    """Fetch dealer details"""
    if dealer_id:
        endpoint = f"/fetchDealer/{dealer_id}"
        dealership = get_request(endpoint)
        return JsonResponse({"status": 200, "dealer": dealership})
    return JsonResponse({"status": 400, "message": "Bad Request"})


def add_review(request):
    """Submit a review"""
    if not request.user.is_anonymous:
        data = json.loads(request.body)
        try:
            post_review(data)
            return JsonResponse({"status": 200})
        except Exception as e:
            logger.error(f"Error posting review: {e}")
            return JsonResponse({"status": 401, "message": "Error in posting review"})
    return JsonResponse({"status": 403, "message": "Unauthorized"})
