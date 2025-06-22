# UTEC Diagram Backend

Este proyecto es un backend serverless para la generación y gestión de diagramas en la nube, desarrollado para la Universidad de Ingeniería y Tecnología (UTEC). Permite a los usuarios autenticarse, crear diagramas (por ejemplo, de arquitectura AWS), almacenarlos y consultarlos de manera segura utilizando AWS Lambda, API Gateway, S3 y DynamoDB.

## Características principales

- **Autenticación de usuarios** (registro, login, perfil) con JWT.
- **Generación de diagramas** a partir de código fuente usando la librería [Diagrams](https://diagrams.mingrammer.com/).
- **Almacenamiento seguro** de diagramas y metadatos en S3.
- **Gestión de usuarios** y perfiles en DynamoDB.
- **API RESTful** protegida con authorizer personalizado.
- **Despliegue serverless** usando Serverless Framework.

## Estructura del proyecto

- `auth.py`: Funciones de autenticación, registro, login, perfil y authorizer JWT.
- `diagrams.py`: Funciones para validar, ejecutar y almacenar diagramas, así como para listar los diagramas de un usuario.
- `serverless.yml`: Configuración de recursos AWS, funciones Lambda y endpoints.
- `README.md`: Este archivo.

## Endpoints principales

| Método | Ruta                   | Descripción                        | Autenticación |
|--------|------------------------|------------------------------------|---------------|
| POST   | `/auth/signup`         | Registro de usuario                | No            |
| POST   | `/auth/login`          | Login de usuario                   | No            |
| GET    | `/auth/profile`        | Obtener perfil de usuario          | Sí            |
| PUT    | `/auth/profile`        | Actualizar perfil de usuario       | Sí            |
| POST   | `/diagrams/generate`   | Generar y guardar un diagrama      | Sí            |
| GET    | `/diagrams/user`       | Listar diagramas del usuario       | Sí            |

## Variables de entorno requeridas

- `S3_BUCKET`: Nombre del bucket S3 para diagramas.
- `USERS_TABLE`: Nombre de la tabla DynamoDB de usuarios.
- `JWT_SECRET`: Secreto para firmar/verificar JWT.
- `CORS_ORIGIN`: Origen permitido para CORS (opcional).

## Despliegue

1. Instala dependencias:
   ```bash
   pip3 install -r requirements.txt -t .
   npm install -g serverless
   ```

2. Configura tus variables de entorno en AWS
```bash
export JWT_SECRET="mi_clave_super_secreta_para_hackathon_2025"
export CORS_ORIGIN="*"
```

3. Despliega con Serverless Framework:
   ```bash
   serverless deploy --stage dev
   ```
