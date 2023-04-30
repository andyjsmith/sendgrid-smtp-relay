FROM python:3.11-alpine

ENV RUNNING_IN_DOCKER=true
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
CMD [ "python", "server.py" ]