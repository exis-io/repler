FROM python:2.7

COPY . /opt/exis/repler/

RUN pip install --requirement /opt/exis/repler/requirements.txt

WORKDIR /opt/exis/repler

CMD ["python", "-u", "repler.py"]
