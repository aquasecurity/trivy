#Readme Grupo 4
##Introducción

Trivy

Funcionalidad: Trivy es una herramienta de código abierto que se utiliza para escanear vulnerabilidades en contenedores, imágenes de Docker, repositorios de código y configuraciones de infraestructura como código (IaC). Su objetivo principal es identificar vulnerabilidades en paquetes y dependencias antes de que las aplicaciones se desplieguen en producción.

Características destacadas:

  Escaneo de imágenes de contenedores: Detecta vulnerabilidades en paquetes del sistema operativo y bibliotecas incluidas en las imágenes de contenedores.

  Análisis de dependencias: Examina las dependencias de proyectos en lenguajes como Ruby, JavaScript y Python en busca de vulnerabilidades conocidas.

  Integración en CI/CD: Se integra fácilmente en pipelines de integración y entrega continua, permitiendo automatizar el escaneo de seguridad antes del despliegue.

Trivy es ideal para equipos de desarrollo y operaciones que utilizan tecnologías de contenedores y desean garantizar que sus imágenes y dependencias estén libres de vulnerabilidades antes de su implementación.

Referencias:

  Análisis de contenedores utilizando TRIVY – IberAsync.es - https://iberasync.es/analisis-de-contenedores-utilizando-trivy/

  Container vulnerability scanning with Trivy – Bluetab - https://www.bluetab.net/en/container-vulnerability-scanning-with-trivy/

  
Complementos útiles: Autoruns y TCPView

Aunque Trivy es la mejor opción para analizar seguridad en contenedores y aplicaciones modernas, existen otras herramientas que pueden complementar su uso cuando trabajamos con sistemas Windows tradicionales o queremos monitorear procesos y conexiones en ejecución.
  Autoruns: Control sobre procesos de inicio en Windows

¿Para qué sirve?
Autoruns permite ver qué programas se inician automáticamente en Windows, ayudando a identificar posibles software malicioso o procesos no deseados que podrían afectar la seguridad del sistema.

Casos de uso complementarios a Trivy:
Si un ataque compromete un servidor Windows, Autoruns ayuda a identificar procesos sospechosos.
Se usa para eliminar malware persistente que se inicia automáticamente.

Referencia:

    Guía de Autoruns en Microsoft Learn - https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns

TCPView: Monitoreo de conexiones de red en tiempo real

¿Para qué sirve?
TCPView permite ver en tiempo real todas las conexiones de red activas en un sistema Windows, facilitando la detección de conexiones sospechosas o tráfico malicioso.

Casos de uso complementarios a Trivy:
Si Trivy detecta vulnerabilidades en un sistema, TCPView ayuda a ver si hay conexiones sospechosas activas.
Es útil para analizar ataques en curso o detectar malware que comunique con servidores externos.

Referencias:

    Guía oficial de TCPView en Microsoft - https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview

Conclusión: ¿Por qué elegir Trivy como herramienta principal?

Trivy es la mejor opción para seguridad en entornos de contenedores y aplicaciones modernas.
Automatiza la detección de vulnerabilidades y se integra con DevOps.
Es de código abierto y ampliamente adoptado en la industria.

Complementando con Autoruns y TCPView:
Si bien Trivy es ideal para escaneo de vulnerabilidades en contenedores y código, herramientas como Autoruns y TCPView pueden ser útiles en seguridad de sistemas Windows, permitiendo monitorear procesos sospechosos y conexiones de red en tiempo real.


Hemos escogido a Trivy como la herramienta principal para el análisis de seguridad debido a su enfoque integral en la detección de vulnerabilidades en contenedores, imágenes de Docker, infraestructura como código (IaC) y dependencias de software. En un entorno donde la seguridad en la nube y la automatización de DevSecOps son fundamentales, Trivy se posiciona como una solución eficiente, rápida y altamente adaptable a los flujos de trabajo modernos.

Además, su compatibilidad con SBOM (Software Bill of Materials) y su capacidad para identificar fallos en configuraciones de seguridad en Kubernetes, Terraform y Docker lo convierten en la mejor opción para evaluar la postura de seguridad en entornos cloud-native.

En comparación con herramientas como Autoruns y TCPView, que están diseñadas para auditorías en sistemas Windows y análisis de tráfico de red respectivamente, Trivy ofrece una solución más amplia y automatizada, alineándose con los estándares actuales de seguridad en la nube y el ciclo de desarrollo seguro.

Por estas razones, el Grupo 4 ha optado por Trivy como la herramienta principal, complementándola con otras soluciones cuando sea necesario para análisis específicos en entornos locales o sistemas operativos tradicionales.

Conclusión:

Trivy es la mejor opción para análisis de vulnerabilidades en entornos modernos como Kubernetes, Docker y CI/CD, proporcionando detección proactiva y automatizada de riesgos de seguridad.

Autoruns y TCPView pueden ser herramientas complementarias en auditorías de seguridad en Windows, pero no reemplazan la capacidad de análisis de Trivy en contenedores y código.

Recomendación:
Si el entorno de seguridad se enfoca en infraestructura en la nube y DevSecOps, Trivy es la herramienta principal a utilizar. En cambio, si el análisis se realiza en endpoints Windows o redes corporativas, Autoruns y TCPView pueden ser útiles como herramientas secundarias.
