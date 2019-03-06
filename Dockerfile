FROM python:3.7-alpine

RUN apk add --no-cache git

COPY requirements.txt /requirements.txt
RUN pip install --no-cache-dir -r /requirements.txt

RUN addgroup -S app && adduser -S -G app app
USER app

WORKDIR /usr/src/app

COPY server.py ./
COPY authz_admin.py ./
COPY token_service ./token_service/

CMD [ "python", "./server.py" ]
