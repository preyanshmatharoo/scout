FROM alpine:latest

LABEL version="1.0"

RUN apk add \
        build-base \
        libffi-dev \
        python3-dev \
        py3-cryptography \
        zip

RUN apk add aws-cli --update-cache --repository http://dl-3.alpinelinux.org/alpine/edge/testing/ --allow-untrusted

#RUN pip3 install scoutsuite

# This is an update suggested by George Hill.
# There is a bug using the latest version of the Boto3 python library. A downgrade is required for botocore and boto3
# Reference - https://github.com/nccgroup/ScoutSuite/issues/381

#RUN pip3 install -U botocore==1.12.135 boto3==1.9.135



COPY ScoutSuite /ScoutSuite

RUN pip3 install -r /ScoutSuite/requirements.txt

RUN addgroup -g 16000 scoutgroup

RUN adduser -u 15000 -S scoutuser -G scoutgroup
USER scoutuser

RUN mkdir /home/scoutuser/sf_scout /home/scoutuser/.aws /home/scoutuser/sf_scout/report
#RUN chown scoutuser /home/scoutuser/sf_scout /home/scoutuser/sf_scout/.aws /home/scoutuser/sf_scout/report

#USER scoutuser

COPY sf_scout.py /home/scoutuser/sf_scout

WORKDIR /home/scoutuser/sf_scout
