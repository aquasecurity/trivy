# Readme Grupo 4
## Introducción
Trivy es una herramienta que permite escánear vulnerabilidades de codigo de imagenes contenedoras.

## Descripcion
Trivy es un escáner de seguridad integral y versátil desarrollado por Aqua Security. Está diseñado para identificar vulnerabilidades y problemas de configuración en una amplia gama de objetivos, incluyendo imágenes de contenedores, sistemas de archivos, repositorios de código, máquinas virtuales, clústeres de Kubernetes y entornos en la nube. 

## Funcionalidades principales

### •	Escaneo de imágenes de contenedores
Trivy analiza imágenes de contenedores en busca de vulnerabilidades conocidas en paquetes del sistema operativo y dependencias de aplicaciones. Soporta múltiples sistemas operativos y gestores de paquetes, como Alpine, RHEL, CentOS, Debian, Ubuntu, npm, yarn, entre otros. 

### •	Análisis de sistemas de archivos y repositorios de código
Permite escanear sistemas de archivos locales y repositorios de código (tanto locales como remotos) para detectar vulnerabilidades en dependencias y configuraciones. Es compatible con diversos lenguajes y entornos de desarrollo. 

### •	Detección de problemas de configuración y secretos
Identifica problemas de configuración en infraestructuras como código (IaC) y busca información sensible o secretos que puedan estar expuestos en el código o en la configuración. 

### •	Análisis de licencias de software
Trivy evalúa las licencias de las dependencias utilizadas, ayudando a garantizar el cumplimiento con las políticas de licencias y evitando posibles conflictos legales. 

### •	Integración en pipelines CI/CD
Trivy está diseñado para integrarse fácilmente en pipelines de integración y entrega continua, permitiendo escaneos automáticos durante el proceso de desarrollo y asegurando que las vulnerabilidades se detecten y aborden tempranamente. 

### •	Operador Trivy para Kubernetes
El Trivy Operator extiende las capacidades de Trivy al entorno de Kubernetes, realizando escaneos continuos de seguridad en clústeres y generando informes detallados sobre los recursos y configuraciones. 

### •	Compatibilidad con múltiples plataformas
Trivy es compatible con una amplia variedad de plataformas y entornos, incluyendo diferentes distribuciones de sistemas operativos, gestores de paquetes y lenguajes de programación, garantizando una cobertura amplia en diversos escenarios. 

## Referencias
- CloudThat. (2024). Detecting and Fixing Vulnerabilities in Docker Images with Trivy and Best Practices. Recuperado de https://www.cloudthat.com/resources/blog/detecting-and-fixing-vulnerabilities-in-docker-images-with-trivy-and-best-practices
- Trivy. Ecosystem. Recuperado de https://trivy.dev/v0.59/ecosystem/
- Aqua. (2021). Trivy´s Journey: From personal project to Open Source Scanner of Choice. Recuperado de https://www.aquasec.com/blog/trivy-scanner/
- Medium. (2024). Catching Vulnerabilities in Your Docker Images: The Power of trivy. Recuperado de https://medium.com/%40sachinsoni600517/catching-vulnerabilities-in-your-docker-images-the-power-of-trivy-6c86494b0564
