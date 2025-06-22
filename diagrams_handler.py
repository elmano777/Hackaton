import json
import boto3
import os
import uuid
from datetime import datetime
import base64
from io import BytesIO
import tempfile
import subprocess
import sys
from decimal import Decimal

# Importar Diagrams
from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import EC2, Lambda, ECS
from diagrams.aws.database import RDS, DynamodbTable
from diagrams.aws.network import ELB, Route53, CloudFront
from diagrams.aws.storage import S3
from diagrams.aws.analytics import EMR, Redshift
from diagrams.aws.integration import SQS, SNS
from diagrams.aws.security import IAM, Cognito
import sys
print("DEBUG sys.path:", sys.path)


s3_client = boto3.client('s3')
S3_BUCKET = os.environ.get('S3_BUCKET')

def cors_headers():
    return {
        'Access-Control-Allow-Origin': os.environ.get('CORS_ORIGIN', '*'),
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
    }

# Custom JSON encoder para manejar Decimal
class DecimalEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Decimal):
            if obj % 1 == 0:
                return int(obj)
            else:
                return float(obj)
        return super(DecimalEncoder, self).default(obj)

def response(status_code, body):
    return {
        'statusCode': status_code,
        'headers': cors_headers(),
        'body': json.dumps(body, cls=DecimalEncoder)
    }

def validate_diagram_code(code, diagram_type):
    """Valida el código del diagrama según el tipo"""
    if not code or not code.strip():
        return False, "El código no puede estar vacío"
    
    if diagram_type == 'aws':
        # Validaciones básicas para diagramas AWS
        if 'Diagram' not in code:
            return False, "El código debe contener una definición de Diagram"
    
    return True, "Válido"

def execute_diagram_code(code, diagram_name, temp_dir):
    """Ejecuta el código de diagrama y genera la imagen"""
    try:
        # Reemplazar dinámicamente el parámetro 'filename' si no está presente
        if "with Diagram(" in code and "filename=" not in code:
            def add_filename(match):
                inside = match.group(1)
                if inside.strip():
                    return f"with Diagram({inside}, filename=r'{os.path.join(temp_dir, diagram_name)}'"
                else:
                    return f"with Diagram(filename=r'{os.path.join(temp_dir, diagram_name)}'"
            import re
            code = re.sub(r"with Diagram\((.*?)\)", add_filename, code)

        # Crear archivo temporal con el código
        code_file = os.path.join(temp_dir, f"{diagram_name}.py")
        with open(code_file, 'w') as f:
            f.write(code)

        # Cargar y ejecutar el código en un módulo temporal
        import importlib.util
        import sys

        spec = importlib.util.spec_from_file_location(diagram_name, code_file)
        module = importlib.util.module_from_spec(spec)
        sys.modules[diagram_name] = module
        spec.loader.exec_module(module)

        # Buscar el archivo PNG generado
        png_file = os.path.join(temp_dir, f"{diagram_name}.png")
        if os.path.exists(png_file):
            with open(png_file, 'rb') as f:
                return f.read(), None
        else:
            # Buscar cualquier archivo .png en caso el nombre no coincida
            for fname in os.listdir(temp_dir):
                if fname.endswith(".png"):
                    with open(os.path.join(temp_dir, fname), 'rb') as f:
                        return f.read(), None
            return None, "No se pudo generar la imagen del diagrama"

    except Exception as e:
        return None, f"Error interno: {str(e)}"


def generate(event, context):
    try:
        print(f"Event completo: {json.dumps(event, cls=DecimalEncoder)}")
        
        # Verificar que el evento tenga el contexto de autorización
        if not event.get('requestContext') or not event['requestContext'].get('authorizer'):
            print("Error: No se encontró contexto de autorización")
            return response(401, {'error': 'No autorizado - token requerido'})
        
        # Obtener información del usuario del contexto del authorizer
        user_id = event['requestContext']['authorizer']['user_id']
        user_email = event['requestContext']['authorizer']['email']
        
        print(f"Usuario autenticado: {user_email} (ID: {user_id})")
        
        # Debug: Imprimir el body raw
        raw_body = event.get('body', '')
        print(f"Raw body: {raw_body}")
        print(f"Body type: {type(raw_body)}")
        print(f"Body length: {len(raw_body) if raw_body else 0}")
        
        # Verificar si el body existe y no está vacío
        if not raw_body:
            return response(400, {'error': 'Request body is empty'})
        
        # Intentar parsear el JSON con mejor manejo de errores
        try:
            # Si el body es string, parsearlo
            if isinstance(raw_body, str):
                body = json.loads(raw_body)
            else:
                body = raw_body
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            print(f"Error at position: {e.pos}")
            print(f"Error context: {raw_body[max(0, e.pos-50):e.pos+50]}")
            return response(400, {
                'error': 'Invalid JSON format',
                'details': str(e),
                'position': e.pos
            })
        
        print(f"Parsed body: {json.dumps(body, cls=DecimalEncoder)}")
        
        code = body.get('code')
        diagram_type = body.get('type', 'aws')
        diagram_name = body.get('name', f'diagram_{uuid.uuid4().hex[:8]}')
        
        print(f"Code length: {len(code) if code else 0}")
        print(f"Diagram type: {diagram_type}")
        print(f"Diagram name: {diagram_name}")
        
        # Validar entrada
        is_valid, error_msg = validate_diagram_code(code, diagram_type)
        if not is_valid:
            return response(400, {'error': error_msg})
        
        # Crear directorio temporal
        with tempfile.TemporaryDirectory() as temp_dir:
            print(f"Using temp directory: {temp_dir}")
            
            # Generar diagrama
            image_data, error = execute_diagram_code(code, diagram_name, temp_dir)
            
            if error:
                print(f"Diagram execution error: {error}")
                return response(400, {'error': error})
            
            print(f"Image generated successfully, size: {len(image_data)} bytes")
            
            # Generar ID único para el diagrama
            diagram_id = str(uuid.uuid4())
            timestamp = datetime.now().isoformat()
            
            # Subir código fuente a S3
            code_key = f"{user_id}/{diagram_type}/{diagram_id}/source.py"
            s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=code_key,
                Body=code,
                ContentType='text/plain'
            )
            print(f"Code uploaded to S3: {code_key}")
            
            # Subir imagen a S3
            image_key = f"{user_id}/{diagram_type}/{diagram_id}/diagram.png"
            s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=image_key,
                Body=image_data,
                ContentType='image/png'
            )
            print(f"Image uploaded to S3: {image_key}")
            
            # Subir metadata
            metadata = {
                'id': diagram_id,
                'name': diagram_name,
                'type': diagram_type,
                'user_id': user_id,
                'user_email': user_email,
                'created_at': timestamp,
                'code_key': code_key,
                'image_key': image_key
            }
            
            metadata_key = f"{user_id}/{diagram_type}/{diagram_id}/metadata.json"
            s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=metadata_key,
                Body=json.dumps(metadata, cls=DecimalEncoder),
                ContentType='application/json'
            )
            print(f"Metadata uploaded to S3: {metadata_key}")
            
            # Generar URL presignada para la imagen
            image_url = s3_client.generate_presigned_url(
                'get_object',
                Params={'Bucket': S3_BUCKET, 'Key': image_key},
                ExpiresIn=3600
            )
            
            return response(200, {
                'diagram_id': diagram_id,
                'image_url': image_url,
                'message': 'Diagrama generado exitosamente'
            })
            
    except KeyError as e:
        print(f"Error de clave faltante: {e}")
        return response(400, {'error': f'Datos requeridos faltantes: {str(e)}'})
    except Exception as e:
        print(f"Error en generate: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return response(500, {'error': f'Error interno: {str(e)}'})

def get_user_diagrams(event, context):
    try:
        # Obtener información del usuario
        user_id = event['requestContext']['authorizer']['user_id']
        
        # Listar diagramas del usuario
        prefix = f"{user_id}/"
        
        response_data = s3_client.list_objects_v2(
            Bucket=S3_BUCKET,
            Prefix=prefix,
            Delimiter='/'
        )
        
        diagrams = []
        
        if 'CommonPrefixes' in response_data:
            for prefix_info in response_data['CommonPrefixes']:
                diagram_prefix = prefix_info['Prefix']
                
                # Obtener metadata de cada diagrama
                try:
                    metadata_key = f"{diagram_prefix}metadata.json"
                    metadata_obj = s3_client.get_object(Bucket=S3_BUCKET, Key=metadata_key)
                    metadata = json.loads(metadata_obj['Body'].read())
                    
                    # Generar URL presignada para la imagen
                    image_url = s3_client.generate_presigned_url(
                        'get_object',
                        Params={'Bucket': S3_BUCKET, 'Key': metadata['image_key']},
                        ExpiresIn=3600
                    )
                    
                    diagrams.append({
                        'id': metadata['id'],
                        'name': metadata['name'],
                        'type': metadata['type'],
                        'created_at': metadata['created_at'],
                        'image_url': image_url
                    })
                    
                except Exception as e:
                    continue  # Skip invalid diagrams
        
        return response(200, {'diagrams': diagrams})
        
    except Exception as e:
        print(f"Error en get_user_diagrams: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return response(500, {'error': f'Error interno: {str(e)}'})
