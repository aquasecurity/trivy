FROM maven:3.6.3-jdk-11 

RUN mvn archetype:generate -DgroupId=com.example -DartifactId=web-app -DarchetypeArtifactId=maven-archetype-webapp -DinteractiveMode=false
WORKDIR /web-app
COPY pom.xml .
RUN mvn clean install && mvn package

CMD ["mvn", "dependency:tree"]
