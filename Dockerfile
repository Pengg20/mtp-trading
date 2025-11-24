FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    CHROME_PATH=/usr/bin/chromium \
    CHROMEDRIVER_PATH=/usr/bin/chromedriver

RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    chromium-driver \
    fonts-noto-cjk \
    libglib2.0-0 \
    libnss3 \
    libxss1 \
    libasound2 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libgtk-3-0 \
    libx11-6 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && if [ ! -e /usr/bin/chromium-browser ]; then ln -s /usr/bin/chromium /usr/bin/chromium-browser; fi

WORKDIR /app

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "scraper.py"]