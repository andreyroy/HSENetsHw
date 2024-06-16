FROM python:3

RUN pip install scapy validators

COPY mtu_finder.py /mtu_finder.py

ENTRYPOINT ["python", "/mtu_finder.py"]