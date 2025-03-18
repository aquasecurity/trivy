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
- Trivy Operator. (2022).Recuperado de https://aquasecurity.github.io/trivy-operator/latest/
- Trivy. Recuperado de https://trivy.dev/v0.17.2
- Trivy. Repositorio de codigo. Recuperado de https: https://trivy.dev/latest/docs/target/repository/

