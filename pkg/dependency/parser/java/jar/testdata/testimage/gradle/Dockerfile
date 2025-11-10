FROM gradle:6.8.1-jdk 
RUN gradle init --type java-application
COPY build.gradle app/
RUN gradle war
