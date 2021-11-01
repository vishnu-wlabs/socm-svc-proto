FROM python:3.8
ENV SRC_DIR /usr/bin/src/webapp/src
COPY src/* ${SRC_DIR}/
#COPY config/sap-certs/*.pem /usr/bin/src/certs/ca-bundle.crt
WORKDIR ${SRC_DIR}

ENV PYTHONUNBUFFERED=1
RUN pip install -r requirements.txt
CMD ["python3", "app.py"]