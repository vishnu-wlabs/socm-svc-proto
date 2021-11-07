FROM python:3.8

COPY requirements.txt /
RUN pip3 install -r /requirements.txt


COPY . /app
WORKDIR /app

ENV FLASK_APP=flaskAppServer
RUN chmod +x ./gunicorn_starter.sh

ENTRYPOINT ["./gunicorn_starter.sh"]