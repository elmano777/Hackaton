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

# Importar Diagrams
from diagrams import Diagram, Cluster, Edge
from diagrams.aws.compute import EC2, Lambda, ECS
from diagrams.aws.database import RDS, DynamodbTable
from diagrams.aws.network import ELB, Route53, CloudFront
from diagrams.aws.storage import S3
from diagrams.aws.analytics import EMR, Redshift
from diagrams.aws.integration import SQS, SNS
from diagrams.aws.security import IAM, Cognito

s3_client = boto3.client('s3')
S3_BUCKET = os.environ.get('S3_BUCKET')

def cors_headers():
    return {
        'Access-Control-Allow-Origin': os.environ.get('CORS_ORIGIN', '*'),
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
    }

def response(status_code, body):
    return {
        'statusCode': status_code,
        'headers': cors_headers(),
        'body': json.dumps(body)
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
        # Crear archivo temporal con el código
        code_file = os.path.join(temp_dir, f"{diagram_name}.py")
        with open(code_file, 'w') as f:
            f.write(code)
        
        # Ejecutar el código
        result = subprocess.run([
            sys.executable, code_file
        ], capture_output=True, text=True, cwd=temp_dir)
        
        if result.returncode != 0:
            return None, f"Error al ejecutar el diagrama: {result.stderr}"
        
        # Buscar el archivo PNG generado
        png_file = os.path.join(temp_dir, f"{diagram_name}.png")
        if os.path.exists(png_file):
            with open(png_file, 'rb') as f:
                return f.read(), None
        else:
            return None, "No se pudo generar la imagen del diagrama"
            
    except Exception as e:
        return None, f"Error interno: {str(e)}"

def generate(event, context):
    try:
        # Obtener información del usuario del contexto del authorizer
        user_id = event['requestContext']['authorizer']['user_id']
        user_email = event['requestContext']['authorizer']['email']
        
        body = json.loads(event['body'])
        code = body.get('code')
        diagram_type = body.get('type', 'aws')
        diagram_name = body.get('name', f'diagram_{uuid.uuid4().hex[:8]}')
        
        # Validar entrada
        is_valid, error_msg = validate_diagram_code(code, diagram_type)
        if not is_valid:
            return response(400, {'error': error_msg})
        
        # Crear directorio temporal
        with tempfile.TemporaryDirectory() as temp_dir:
            # Generar diagrama
            image_data, error = execute_diagram_code(code, diagram_name, temp_dir)
            
            if error:
                return response(400, {'error': error})
            
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
            
            # Subir imagen a S3
            image_key = f"{user_id}/{diagram_type}/{diagram_id}/diagram.png"
            s3_client.put_object(
                Bucket=S3_BUCKET,
                Key=image_key,
                Body=image_data,
                ContentType='image/png'
            )
            
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
                Body=json.dumps(metadata),
                ContentType='application/json'
            )
            
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
            
    except Exception as e:
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
        return response(500, {'error': f'Error interno: {str(e)}'})