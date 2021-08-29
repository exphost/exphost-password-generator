FROM python:3.9
RUN pip install kubernetes kopf jinja2
COPY app /app
CMD kopf run --standalone app/passworder.py
