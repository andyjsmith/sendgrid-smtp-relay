FROM python:3.11-alpine

COPY server.py requirements.txt /app/
WORKDIR /app
RUN pip install -r requirements.txt
CMD [ "python", "server.py" ]