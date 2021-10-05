FROM python:3

RUN mkdir -p /home/app

COPY . /home/app

WORKDIR ./home/app

RUN pip install --no-cache-dir -r requirements.txt 

ENTRYPOINT ["python","client.py"]