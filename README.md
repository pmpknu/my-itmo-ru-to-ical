# ITMO Schedule to iCalendar - Simplified Version

A standalone Python script that fetches your schedule from my.itmo.ru and converts it to an iCalendar (.ics) file that you can import into any calendar application.

## Features

- ✅ **No Docker required** - just run the Python script
- ✅ **No web server** - generates .ics file directly
- ✅ **Simple usage** - one command to get your calendar
- ✅ **All-in-one file** - entire functionality in `main.py`
- ✅ **Proper iCalendar format** - works with Google Calendar, Apple Calendar, Outlook, etc.
- ✅ **Russian language support** - handles Cyrillic characters correctly
- ✅ **Zoom links included** - adds Zoom URLs to events when available

## Installation

1. **Clone or download this folder**

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

   Or install manually:
   ```bash
   pip install aiohttp python-dateutil
   ```

## Usage

### Method 1: Interactive (script will ask for credentials)
```bash
python main.py
```

### Method 2: Environment variables
```bash
export ITMO_USERNAME="your_itmo_username"
export ITMO_PASSWORD="your_itmo_password"
python main.py
```

### Method 3: Custom output file
```bash
export ITMO_USERNAME="your_itmo_username"
export ITMO_PASSWORD="your_itmo_password"
export OUTPUT_FILE="my_schedule.ics"
python main.py
```

## What happens when you run the script

1. **Authentication** - Logs into my.itmo.ru using OAuth2
2. **Data fetching** - Downloads your personal schedule for the current academic year
3. **Conversion** - Converts lessons to iCalendar format with:
   - Lesson type tags (Лек, Прак, Лаб, etc.)
   - Room and building information
   - Teacher information
   - Zoom links (if available)
   - Proper Moscow time (MSK) timezone
4. **File creation** - Saves as `itmo_schedule.ics` (or custom filename)

## License

This is a simplified version of the original [my-itmo-ru-to-ical](https://github.com/iburakov/my-itmo-ru-to-ical) project by Ilya Burakov, used under MIT license.
