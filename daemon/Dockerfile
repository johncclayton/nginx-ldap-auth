FROM python:2-alpine

# Install required software
RUN \
    apk --no-cache add libffi-dev python-dev openssl-dev openldap-dev && \
    apk --no-cache add --virtual build-dependencies build-base && \
    pip install python-ldap cryptography && \
    apk del build-dependencies

EXPOSE 8888
WORKDIR /code
COPY entrypoint.sh /code
COPY nginx-ldap-auth-daemon.py /code

#CMD ["python", "-u", "/code/nginx-ldap-auth-daemon.py", "--host", "0.0.0.0", "--port", "8888"]

CMD [ "/code/entrypoint.sh" ]
