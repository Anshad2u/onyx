from onyx.db.enums import ExternalAppType
from onyx.external_apps.providers.google_base import GoogleOAuthProvider


class GoogleCalendarProvider(GoogleOAuthProvider):
    spec = GoogleOAuthProvider.build_spec(
        app_type=ExternalAppType.GOOGLE_CALENDAR,
        app_name="Google Calendar",
        scope="https://www.googleapis.com/auth/calendar",
        upstream_url_patterns=["https://www\\.googleapis\\.com/calendar/.*"],
        description=(
            "Read and create events on your Google Calendar from inside Onyx Craft."
        ),
        google_api_name="Google Calendar API",
    )
