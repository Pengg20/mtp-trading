$ErrorActionPreference = 'Stop'

# Require credentials and links file
if (-not $env:SIGNALSAHAM_EMAIL -or -not $env:SIGNALSAHAM_PASSWORD) {
  Write-Host "SIGNALSAHAM_EMAIL/SIGNALSAHAM_PASSWORD not set. Exiting."; exit 1
}
if (-not $env:LINKS_FILE) { $env:LINKS_FILE = "d:\var\shm\backend\link-name-stock.txt" }

# Schedule config
if (-not $env:AUTO_SCHEDULE) { $env:AUTO_SCHEDULE = 'true' }
if (-not $env:SCHEDULE_TIMES) { $env:SCHEDULE_TIMES = '10:02,12:02,14:02,17:32' }
if (-not $env:UPDATE_MODE) { $env:UPDATE_MODE = 'append' }
if (-not $env:SKIP_EXISTING) { $env:SKIP_EXISTING = 'false' }
if (-not $env:REFRESH_RETRY) { $env:REFRESH_RETRY = 'true' }
if (-not $env:RATE_LIMIT_MS) { $env:RATE_LIMIT_MS = '800' }
if (-not $env:AGGREGATE_AFTER) { $env:AGGREGATE_AFTER = 'true' }

Push-Location "d:\var\shm"
try {
  python "d:\var\shm\scraper.py"
} finally {
  Pop-Location
}