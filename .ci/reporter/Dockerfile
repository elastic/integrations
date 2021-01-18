FROM python:3.9.1-slim-buster
RUN pip install -U \
    pip \
    setuptools \
    wheel
WORKDIR /project
RUN useradd -m -r user && \
    chown user /project
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY . .
USER user
ENTRYPOINT ["python", "./report.py"]