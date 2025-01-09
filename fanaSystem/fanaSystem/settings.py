"""
Django settings for fanaSystem project.

Generated by 'django-admin startproject' using Django 5.0.7.

For more information on this file, see
https://docs.djangoproject.com/en/5.0/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/5.0/ref/settings/
"""

from pathlib import Path
import os
import socket

#import environ
# from google.cloud import secretmanager

# Initialize environment variables
#env = environ.Env()
#environ.Env.read_env()  # Reads local .env for development
def get_secret(secret_name):
    return None
    # """
    # Retrieve secret from Google Secret Manager.
    # """
    # try:
    #     client = secretmanager.SecretManagerServiceClient()
    #     name = f"projects/local-tracker-441721-v0/secrets/{secret_name}/versions/latest"
    #     response = client.access_secret_version(name=name)
    #     return response.payload.data.decode("UTF-8")
    # except Exception as e:
    #     print(f"Error retrieving secret: {e}")
    #     return None


# Fetch the secret key
SECRET_KEY = get_secret("django_settings") or os.getenv("SECRET_KEY", "your_default_secret_key")

# Get the server’s IP address or hostname
DEFAULT_SERVER_HOST = socket.gethostbyname(socket.gethostname())

# Environment variable to override with a custom AUTH_SERVER_IP if needed
AUTH_SERVER_IP = os.getenv("AUTH_SERVER_IP", DEFAULT_SERVER_HOST)

# Construct the full URL for the authentication endpoint
AUTH_SERVER_LOGIN_URL = f"http://localhost:8000/fanaAuthenticator/api/token/"

SEND_ORDER_TO_DASHBOARD_URL = f"http://localhost:8000/fanaDashboard/receiveOrder/"

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/5.0/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
# SECRET_KEY = "django-insecure-yanopv@xd)#_v3ixk0d&6+a!v&jn(-l-b*et&c$(4#=x=1#55("

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True #env.bool("DEBUG", default=False)

# SECURITY WARNING: update this when you have the production host
ALLOWED_HOSTS = ['*']


# Application definition

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "daphne",
    "django.contrib.staticfiles",
    "fanaDashboard",
    "fanaCallSetup",
    "channels",
    "fanaAuthenticator",
    "corsheaders",
]

ASGI_APPLICATION = 'fanaSystem.asgi.application'

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "fanaDashboard.middleware.JWTAuthenticationMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "corsheaders.middleware.CorsMiddleware",
]
SECURE_COOKIES = False  # Change to True in production

CORS_ALLOW_ALL_ORIGINS = True


ROOT_URLCONF = "fanaSystem.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [os.path.join(BASE_DIR, 'templates')],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "fanaSystem.wsgi.application"




# Database
# https://docs.djangoproject.com/en/5.0/ref/settings/#databases

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}


# import os

# if os.getenv("DB_HOST"):
#     DATABASES = {
#         "default": {
#             "ENGINE": "django.db.backends.postgresql",
#             "NAME": os.getenv("DB_NAME", "mydatabase"),
#             "USER": os.getenv("DB_USER", "myuser"),
#             "PASSWORD": os.getenv("DB_PASSWORD", "mypassword"),
#             "HOST": os.getenv("DB_HOST"),
#             "PORT": os.getenv("DB_PORT", "5432"),
#         }
#     }
# else:
#     DATABASES = {
#         "default": {
#             "ENGINE": "django.db.backends.sqlite3",
#             "NAME": os.path.join(BASE_DIR, "db.sqlite3"),
#         }
#     }



# Password validation
# https://docs.djangoproject.com/en/5.0/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/5.0/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = "UTC"

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/5.0/howto/static-files/

# STATIC_URL = "static/"

# Default primary key field type
# https://docs.djangoproject.com/en/5.0/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

STATIC_URL = '/static/'
STATICFILES_DIRS = [
    os.path.join(BASE_DIR, 'fanaCallSetup', 'static'),
    os.path.join(BASE_DIR, 'fanaDashboard', 'static'),
]
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')


STATIC_URL = '/static/'
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')


# fanaSystem/settings.py
LOGIN_URL = '/fanaDashboard/login/'
LOGIN_REDIRECT_URL = '/fanaDashboard/'

# settings.py



# Channels Settings
ASGI_APPLICATION = "fanaSystem.asgi.application"

# Redis Channel Layer
CHANNEL_LAYERS = {
    "default": {
        "BACKEND": "channels_redis.core.RedisChannelLayer",
        "CONFIG": {
            "hosts": [("127.0.0.1", 6379)],  # Redis server details
        },
    },
}



from datetime import timedelta

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ),

    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',  # Ensure authentication by default
    ],
}

from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': False,
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': SECRET_KEY,  # Ensure this is consistent across services
    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
}


# settings.py
LOGIN_URL = '/fanaDashboard/login/'


