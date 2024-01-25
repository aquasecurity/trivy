FROM alpine:3.5
RUN zypper install bash
RUN pip install --no-cache-dir -r /usr/src/app/requirements.txt
USER mike
CMD python /usr/src/app/app.py