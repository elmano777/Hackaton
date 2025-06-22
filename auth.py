import json
import jwt
import bcrypt
import boto3
import os
import uuid
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

# DynamoDB client
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table(os.environ['USERS_TABLE'])

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

def validate_email(email):
    """Validación básica de email"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    """Validación de contraseña - mínimo 8 caracteres"""
    return len(password) >= 8

def get_user_by_email(email):
    """Obtiene un usuario por email desde DynamoDB"""
    try:
        response = users_table.get_item(Key={'email': email})
        return response.get('Item')
    except ClientError as e:
        print(f"Error al obtener usuario: {e}")
        return None

def create_user(email, name, hashed_password):
    """Crea un nuevo usuario en DynamoDB"""
    try:
        user_id = str(uuid.uuid4())
        user_data = {
            'email': email,
            'user_id': user_id,
            'name': name,
            'password': hashed_password.decode('utf-8'),  # DynamoDB no soporta bytes
            'created_at': datetime.now().isoformat(),
            'updated_at': datetime.now().isoformat(),
            'is_active': True,
            'login_count': 0
        }
        
        users_table.put_item(
            Item=user_data,
            ConditionExpression='attribute_not_exists(email)'  # Evita duplicados
        )
        
        return user_data
    except ClientError as e:
        if e.response['Error']['Code'] == 'ConditionalCheckFailedException':
            return None  # Usuario ya existe
        print(f"Error al crear usuario: {e}")
        raise e

def update_user_login(email):
    """Actualiza información de login del usuario"""
    try:
        users_table.update_item(
            Key={'email': email},
            UpdateExpression='SET login_count = login_count + :inc, last_login = :timestamp',
            ExpressionAttributeValues={
                ':inc': 1,
                ':timestamp': datetime.now().isoformat()
            }
        )
    except ClientError as e:
        print(f"Error al actualizar login: {e}")

def signup(event, context):
    try:
        body = json.loads(event['body'])
        email = body.get('email', '').lower().strip()
        password = body.get('password', '')
        name = body.get('name', '').strip()
        
        # Validaciones
        if not email or not password or not name:
            return response(400, {'error': 'Email, password y name son requeridos'})
        
        if not validate_email(email):
            return response(400, {'error': 'Email inválido'})
        
        if not validate_password(password):
            return response(400, {'error': 'La contraseña debe tener al menos 8 caracteres'})
        
        if len(name) < 2:
            return response(400, {'error': 'El nombre debe tener al menos 2 caracteres'})
        
        # Verificar si el usuario ya existe
        existing_user = get_user_by_email(email)
        if existing_user:
            return response(400, {'error': 'El usuario ya existe'})
        
        # Hash de la contraseña
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        
        # Crear usuario
        user = create_user(email, name, hashed_password)
        if not user:
            return response(400, {'error': 'El usuario ya existe'})
        
        return response(201, {
            'message': 'Usuario creado exitosamente',
            'user': {
                'user_id': user['user_id'],
                'email': user['email'],
                'name': user['name']
            }
        })
        
    except json.JSONDecodeError:
        return response(400, {'error': 'JSON inválido'})
    except Exception as e:
        print(f"Error en signup: {e}")
        return response(500, {'error': 'Error interno del servidor'})

def login(event, context):
    try:
        body = json.loads(event['body'])
        email = body.get('email', '').lower().strip()
        password = body.get('password', '')
        
        if not email or not password:
            return response(400, {'error': 'Email y password son requeridos'})
        
        if not validate_email(email):
            return response(400, {'error': 'Email inválido'})
        
        # Verificar usuario
        user = get_user_by_email(email)
        if not user:
            return response(401, {'error': 'Credenciales inválidas'})
        
        if not user.get('is_active', True):
            return response(401, {'error': 'Cuenta desactivada'})
        
        # Verificar contraseña
        stored_password = user['password'].encode('utf-8')
        if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
            return response(401, {'error': 'Credenciales inválidas'})
        
        # Actualizar información de login
        update_user_login(email)
        
        # Generar JWT token
        payload = {
            'user_id': user['user_id'],
            'email': email,
            'name': user['name'],
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(hours=24)
        }
        
        token = jwt.encode(payload, os.environ['JWT_SECRET'], algorithm='HS256')
        
        return response(200, {
            'token': token,
            'expires_in': 86400,  # 24 horas en segundos
            'user': {
                'user_id': user['user_id'],
                'email': email,
                'name': user['name']
            }
        })
        
    except json.JSONDecodeError:
        return response(400, {'error': 'JSON inválido'})
    except Exception as e:
        print(f"Error en login: {e}")
        return response(500, {'error': 'Error interno del servidor'})

def get_profile(event, context):
    """Obtiene el perfil del usuario autenticado"""
    try:
        # Obtener información del usuario del contexto del authorizer
        user_email = event['requestContext']['authorizer']['email']
        
        user = get_user_by_email(user_email)
        if not user:
            return response(404, {'error': 'Usuario no encontrado'})
        
        return response(200, {
            'user': {
                'user_id': user['user_id'],
                'email': user['email'],
                'name': user['name'],
                'created_at': user['created_at'],
                'login_count': user.get('login_count', 0),
                'last_login': user.get('last_login')
            }
        })
        
    except Exception as e:
        print(f"Error en get_profile: {e}")
        return response(500, {'error': 'Error interno del servidor'})

def update_profile(event, context):
    """Actualiza el perfil del usuario"""
    try:
        user_email = event['requestContext']['authorizer']['email']
        body = json.loads(event['body'])
        
        name = body.get('name', '').strip()
        
        if not name:
            return response(400, {'error': 'El nombre es requerido'})
        
        if len(name) < 2:
            return response(400, {'error': 'El nombre debe tener al menos 2 caracteres'})
        
        # Actualizar usuario
        users_table.update_item(
            Key={'email': user_email},
            UpdateExpression='SET #name = :name, updated_at = :timestamp',
            ExpressionAttributeNames={'#name': 'name'},
            ExpressionAttributeValues={
                ':name': name,
                ':timestamp': datetime.now().isoformat()
            }
        )
        
        return response(200, {'message': 'Perfil actualizado exitosamente'})
        
    except json.JSONDecodeError:
        return response(400, {'error': 'JSON inválido'})
    except Exception as e:
        print(f"Error en update_profile: {e}")
        return response(500, {'error': 'Error interno del servidor'})

def authorizer(event, context):
    """Lambda Authorizer para validar JWT tokens"""
    try:
        token = event['authorizationToken']
        
        if not token or not token.startswith('Bearer '):
            raise Exception('Unauthorized')
        
        # Extraer el token
        jwt_token = token.replace('Bearer ', '')
        
        # Verificar el token
        payload = jwt.decode(jwt_token, os.environ['JWT_SECRET'], algorithms=['HS256'])
        
        # Verificar si el usuario existe y está activo
        user = get_user_by_email(payload['email'])
        if not user or not user.get('is_active', True):
            raise Exception('Unauthorized')
        
        # Generar policy de autorización
        policy = {
            'principalId': payload['user_id'],
            'policyDocument': {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Action': 'execute-api:Invoke',
                        'Effect': 'Allow',
                        'Resource': event['methodArn']
                    }
                ]
            },
            'context': {
                'user_id': payload['user_id'],
                'email': payload['email'],
                'name': payload['name']
            }
        }
        
        return policy
        
    except jwt.ExpiredSignatureError:
        raise Exception('Token expired')
    except jwt.InvalidTokenError:
        raise Exception('Invalid token')
    except Exception as e:
        print(f"Error en authorizer: {e}")
        raise Exception('Unauthorized')