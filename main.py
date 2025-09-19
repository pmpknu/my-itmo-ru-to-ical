#!/usr/bin/env python3
"""
ITMO Schedule to iCalendar Converter
A standalone script that fetches your schedule from my.itmo.ru and saves it as an .ics file
"""

import asyncio
import html
import logging
import os
import re
import urllib.parse
from base64 import urlsafe_b64encode
from datetime import datetime, timedelta, date
from hashlib import sha256, md5
from typing import Iterable
from uuid import UUID

import aiohttp
from dateutil.parser import isoparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ITMO API Configuration
API_BASE_URL = "https://my.itmo.ru/api"
CLIENT_ID = "student-personal-cabinet"
REDIRECT_URI = "https://my.itmo.ru/login/callback"
PROVIDER = "https://id.itmo.ru/auth/realms/itmo"

# Lesson type mappings
LESSON_TYPE_TO_TAG_MAP = {
    "Лекции": "Лек",
    "Практические занятия": "Прак",
    "Лабораторные занятия": "Лаб",
    "Занятия спортом": "Спорт",
}

RAW_LESSON_KEY_NAMES = {
    "group": "Группа",
    "teacher_name": "Преподаватель",
    "teacher_fio": "Преподаватель",
    "zoom_url": "Ссылка на Zoom",
    "zoom_password": "Пароль Zoom",
    "zoom_info": "Доп. информация для Zoom",
    "note": "Примечание",
}


class ITMOCalendarFetcher:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.session = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()

    def generate_code_verifier(self):
        """Generate PKCE code verifier"""
        code_verifier = urlsafe_b64encode(os.urandom(40)).decode("utf-8")
        return re.sub("[^a-zA-Z0-9]+", "", code_verifier)

    def get_code_challenge(self, code_verifier: str):
        """Generate PKCE code challenge"""
        code_challenge_bytes = sha256(code_verifier.encode("utf-8")).digest()
        code_challenge = urlsafe_b64encode(code_challenge_bytes).decode("utf-8")
        return code_challenge.replace("=", "")

    async def get_access_token(self) -> str:
        """Authenticate with ITMO and get access token"""
        logger.info(f"Getting access token for {self.username}")

        code_verifier = self.generate_code_verifier()
        code_challenge = self.get_code_challenge(code_verifier)

        # Step 1: Get authorization URL
        auth_resp = await self.session.get(
            PROVIDER + "/protocol/openid-connect/auth",
            params={
                "protocol": "oauth2",
                "response_type": "code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "scope": "openid",
                "state": "im_not_a_browser",
                "code_challenge_method": "S256",
                "code_challenge": code_challenge,
            },
        )
        auth_resp.raise_for_status()

        # Step 2: Extract form action from the login page
        form_action_regex = re.compile(rf'"loginAction":\s*"(?P<action>{re.escape(PROVIDER)}[^"]*)"', re.DOTALL)
        form_action_match = form_action_regex.search(await auth_resp.text())
        if not form_action_match:
            raise ValueError("Keycloak form action regexp match not found")
        form_action = html.unescape(form_action_match.group("action"))

        # Step 3: Submit login form
        form_resp = await self.session.post(
            url=form_action,
            data={"username": self.username, "password": self.password},
            cookies=auth_resp.cookies,
            allow_redirects=False,
        )
        if form_resp.status != 302:
            raise ValueError(f"Wrong Keycloak form response: {form_resp.status} {await form_resp.text()}")

        # Step 4: Extract authorization code from redirect
        url_redirected_to = form_resp.headers["Location"]
        query = urllib.parse.urlparse(url_redirected_to).query
        redirect_params = urllib.parse.parse_qs(query)
        auth_code = redirect_params["code"][0]

        # Step 5: Exchange authorization code for access token
        token_resp = await self.session.post(
            url=PROVIDER + "/protocol/openid-connect/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "redirect_uri": REDIRECT_URI,
                "code": auth_code,
                "code_verifier": code_verifier,
            },
            allow_redirects=False,
        )
        token_resp.raise_for_status()
        result = await token_resp.json()
        token = result["access_token"]
        logger.info(f"Successfully got access token for {self.username}")
        return token

    def get_date_range_params(self) -> dict:
        """Get date range for current academic term"""
        pivot = date.today().replace(month=8, day=1)
        this_year = date.today().year
        term_start_year = this_year - 1 if date.today() < pivot else this_year
        return {
            "date_start": f"{term_start_year}-08-01",
            "date_end": f"{term_start_year + 1}-07-31",
        }

    async def get_raw_lessons(self, auth_token: str) -> Iterable[dict]:
        """Fetch raw lesson data from ITMO API"""
        url = API_BASE_URL + "/schedule/schedule/personal"
        params = self.get_date_range_params()
        logger.info(f"Getting data from {url}, using params {params}")

        resp = await self.session.get(
            url, 
            params=params, 
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        resp.raise_for_status()
        resp_json = await resp.json()
        
        days = resp_json["data"]
        return (dict(date=day["date"], **lesson) for day in days for lesson in day["lessons"])


class CalendarEvent:
    """Represents a calendar event"""
    
    def __init__(self, name: str, begin: datetime, end: datetime, description: str = "", location: str = "", uid: str = "", url: str = ""):
        self.name = name
        self.begin = begin
        self.end = end
        self.description = description
        self.location = location
        self.uid = uid
        self.url = url

    def to_ics_string(self) -> str:
        """Convert event to iCalendar format"""
        def format_datetime(dt):
            return dt.strftime("%Y%m%dT%H%M%S")
        
        lines = [
            "BEGIN:VEVENT",
            f"UID:{self.uid}",
            f"DTSTART:{format_datetime(self.begin)}",
            f"DTEND:{format_datetime(self.end)}",
            f"SUMMARY:{self.name}",
        ]
        
        if self.description:
            # Escape special characters in description
            desc = self.description.replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;").replace("\n", "\\n")
            lines.append(f"DESCRIPTION:{desc}")
        
        if self.location:
            loc = self.location.replace("\\", "\\\\").replace(",", "\\,").replace(";", "\\;")
            lines.append(f"LOCATION:{loc}")
        
        if self.url:
            lines.append(f"URL:{self.url}")
        
        lines.append("END:VEVENT")
        return "\n".join(lines)


class CalendarBuilder:
    """Build iCalendar from events"""
    
    @staticmethod
    def lesson_type_to_tag(lesson_type: str) -> str:
        return LESSON_TYPE_TO_TAG_MAP.get(lesson_type, lesson_type)

    @staticmethod
    def raw_lesson_to_description(raw_lesson: dict) -> str:
        lines = []
        for key, name in RAW_LESSON_KEY_NAMES.items():
            if raw_lesson.get(key):
                lines.append(f"{name}: {raw_lesson[key]}")

        msk_formatted_datetime = (datetime.utcnow() + timedelta(hours=3)).strftime("%Y-%m-%d %H:%M")
        lines.append(f"Обновлено: {msk_formatted_datetime} MSK")
        return "\n".join(lines)

    @staticmethod
    def raw_lesson_to_location(raw_lesson: dict) -> str:
        elements = []
        for key in ["room", "building"]:
            if raw_lesson.get(key):
                elements.append(raw_lesson[key])

        result = ", ".join(elements)

        if raw_lesson.get("zoom_url"):
            result = f"Zoom / {result}" if result else "Zoom"

        return result if result else ""

    @staticmethod
    def raw_lesson_to_uuid(raw_lesson: dict) -> str:
        elements = [
            raw_lesson["date"],
            raw_lesson["time_start"],
            raw_lesson["subject"],
        ]
        result = ", ".join(elements)
        md5_of_lesson = md5(result.encode("utf-8")).hexdigest()
        return str(UUID(hex=md5_of_lesson))

    @classmethod
    def raw_lesson_to_event(cls, raw_lesson: dict) -> CalendarEvent:
        """Convert raw lesson data to CalendarEvent"""
        begin = isoparse(f"{raw_lesson['date']}T{raw_lesson['time_start']}:00+03:00")
        end = isoparse(f"{raw_lesson['date']}T{raw_lesson['time_end']}:00+03:00")
        
        # Fix if there's a mistake in event times
        if begin > end:
            begin, end = end, begin
        
        name = f"[{cls.lesson_type_to_tag(raw_lesson['type'])}] {raw_lesson['subject']}"
        description = cls.raw_lesson_to_description(raw_lesson)
        location = cls.raw_lesson_to_location(raw_lesson)
        uid = cls.raw_lesson_to_uuid(raw_lesson)
        url = raw_lesson.get("zoom_url", "")
        
        return CalendarEvent(name, begin, end, description, location, uid, url)

    @staticmethod
    def build_calendar(events: list[CalendarEvent]) -> str:
        """Build complete iCalendar string"""
        lines = [
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//my-itmo-ru-to-ical//EN",
            "CALSCALE:GREGORIAN",
            "METHOD:PUBLISH",
        ]
        
        for event in events:
            lines.append(event.to_ics_string())
        
        lines.append("END:VCALENDAR")
        return "\n".join(lines)


async def main():
    """Main function to fetch and save ITMO calendar"""
    
    # Get credentials from environment variables or prompt user
    username = os.getenv("ITMO_USERNAME")
    password = os.getenv("ITMO_PASSWORD")
    
    if not username:
        username = input("Enter your ITMO username: ").strip()
    if not password:
        import getpass
        password = getpass.getpass("Enter your ITMO password: ")
    
    if not username or not password:
        logger.error("Username and password are required")
        return
    
    output_file = os.getenv("OUTPUT_FILE", "itmo_schedule.ics")
    
    try:
        async with ITMOCalendarFetcher(username, password) as fetcher:
            # Get access token
            token = await fetcher.get_access_token()
            
            # Fetch lessons
            logger.info("Fetching lessons...")
            raw_lessons = await fetcher.get_raw_lessons(token)
            
            # Convert to events
            logger.info("Converting lessons to calendar events...")
            events = [CalendarBuilder.raw_lesson_to_event(lesson) for lesson in raw_lessons]
            
            # Build calendar
            logger.info(f"Building calendar with {len(events)} events...")
            calendar_text = CalendarBuilder.build_calendar(events)
            
            # Save to file
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(calendar_text)
            
            logger.info(f"Calendar saved to {output_file}")
            logger.info(f"You can import this file into Google Calendar, Apple Calendar, or any other calendar app")
            
    except Exception as e:
        logger.error(f"Error: {e}")
        raise


if __name__ == "__main__":
    # Check if required packages are available
    try:
        import aiohttp
        from dateutil.parser import isoparse
    except ImportError as e:
        print(f"Missing required package: {e}")
        print("Install required packages with:")
        print("pip install aiohttp python-dateutil")
        exit(1)
    
    asyncio.run(main())