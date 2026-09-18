"""
Rotas de Autenticação
"""

from flask import Blueprint, request, jsonify
from app.services.auth_service import AuthService
from app.utils.decorators import require_auth
from app import db
from app.models.user import User
from app.models.audit import AuditLog

auth_bp = Blueprint('auth', __name__)
auth_service = AuthService()

@auth_bp.route('/login', methods=['POST'])
def login():
    """
    Autenticar usuário e retornar token JWT
    
    Corpo da Requisição:
        - username: Nome de usuário
        - password: Senha do usuário
    
    Retorna:
        - token: Token JWT
        - user: Informações do usuário
        - expires_in: Tempo de expiração do token em segundos
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Nenhum dado fornecido'}), 400
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Nome de usuário e senha são obrigatórios'}), 400
    
    result = auth_service.authenticate_user(username, password)
    
    if result:
        return jsonify({
            'success': True,
            'token': result['token'],
            'user': result['user'],
            'expires_in': result['expires_in']
        }), 200
    else:
        return jsonify({'error': 'Credenciais inválidas'}), 401

@auth_bp.route('/logout', methods=['POST'])
@require_auth
def logout():
    """
    Deslogar usuário e invalidar token
    
    Cabeçalhos:
        - Authorization: Bearer <token>
    
    Retorna:
        - success: True se logout bem-sucedido
    """
    token = request.token
    
    if auth_service.logout(token):
        return jsonify({'success': True, 'message': 'Deslogado com sucesso'}), 200
    else:
        return jsonify({'error': 'Falha no logout'}), 500

@auth_bp.route('/verify', methods=['GET'])
@require_auth
def verify():
    """
    Verificar validade do token
    
    Cabeçalhos:
        - Authorization: Bearer <token>
    
    Retorna:
        - valid: True se o token é válido
        - user: Informações do usuário
    """
    from app.models.user import User
    
    user = User.query.get(request.user_id)
    
    if user:
        return jsonify({
            'valid': True,
            'user': user.to_dict()
        }), 200
    else:
        return jsonify({'valid': False, 'error': 'Usuário não encontrado'}), 404

@auth_bp.route('/me', methods=['GET'])
@require_auth
def get_current_user():
    """
    Obter informações do usuário atual
    
    Cabeçalhos:
        - Authorization: Bearer <token>
    
    Retorna:
        - user: Informações do usuário atual
    """
    from app.models.user import User
    
    user = User.query.get(request.user_id)
    
    if user:
        return jsonify({'user': user.to_dict()}), 200
    else:
        return jsonify({'error': 'Usuário não encontrado'}), 404

@auth_bp.route('/register', methods=['POST'])
@require_auth
def register_user():
    """
    Registrar novo usuário (apenas para superadmin)
    
    Corpo da Requisição:
        - username: Nome de usuário (obrigatório)
        - email: Email do usuário (obrigatório)
        - sector_id: ID do setor (opcional)
        - role: Papel do usuário - 'viewer', 'admin' ou 'superadmin' (opcional, padrão: 'viewer')
    
    Cabeçalhos:
        - Authorization: Bearer <token> (deve ser superadmin)
    
    Retorna:
        - user: Informações do usuário criado
    """
    current_user = User.query.get(request.user_id)
    if not current_user or current_user.role not in ('superadmin', 'mestre'):
        return jsonify({'error': 'Apenas superadministradores podem criar usuários'}), 403

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Nenhum dado fornecido'}), 400

    username = data.get('username')
    email = data.get('email')
    if not username or not email:
        return jsonify({'error': 'Nome de usuário e email são obrigatórios'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Nome de usuário já existe'}), 409
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email já está em uso'}), 409

    role = data.get('role', 'viewer')

    if role == 'superadmin' and current_user.role != 'mestre':
        return jsonify({'error': 'Apenas o mestre pode criar superadministradores'}), 403

    from app.models.sector import Sector
    from app.models.sector_access import UserSectorAccess

    sector_id = data.get('sector_id')

    # Superadmin sempre ganha setor pessoal proprio + acesso ao TI
    if role == 'superadmin':
        personal = Sector(name=username, description=f'Senhas pessoais de {username}', is_personal=True)
        db.session.add(personal)
        db.session.commit()
        sector_id = personal.id

        ti_sector = Sector.query.filter_by(name='TI').first()
        extra_sectors = [ti_sector.id] if ti_sector and ti_sector.id != sector_id else []
    else:
        extra_sectors = data.get('extra_sector_ids', [])

    new_user = User(
        username=username,
        email=email,
        sector_id=sector_id,
        role=role
    )
    db.session.add(new_user)
    db.session.commit()

    for sid in extra_sectors:
        access = UserSectorAccess(user_id=new_user.id, sector_id=sid)
        db.session.add(access)
    if extra_sectors:
        db.session.commit()
    
    # Registrar ação
    AuditLog.log_action(
        user_id=request.user_id,
        action='CREATE_USER',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=f'Usuário criado: {username}'
    )
    
    return jsonify({
        'success': True,
        'message': 'Usuário criado com sucesso',
        'user': new_user.to_dict()
    }), 201

@auth_bp.route('/users', methods=['GET'])
@require_auth
def list_users():
    """
    Listar todos os usuários (apenas para admins)
    
    Cabeçalhos:
        - Authorization: Bearer <token> (deve ser admin)
    
    Retorna:
        - users: Lista de usuários
    """
    current_user = User.query.get(request.user_id)
    if not current_user or current_user.role not in ('superadmin', 'mestre'):
        return jsonify({'error': 'Apenas superadministradores podem listar usuários'}), 403
    
    users = User.query.order_by(User.username).all()
    
    return jsonify({
        'users': [user.to_dict() for user in users]
    }), 200

@auth_bp.route('/users/<int:user_id>', methods=['PUT'])
@require_auth
def update_user(user_id):
    """
    Atualizar informações de um usuário (apenas para superadmin)
    
    Corpo da Requisição:
        - email: Email do usuário (opcional)
        - sector_id: ID do setor (opcional)
        - role: Papel do usuário (opcional)
        - is_active: Status ativo/inativo (opcional)
    
    Cabeçalhos:
        - Authorization: Bearer <token> (deve ser superadmin)
    
    Retorna:
        - user: Informações do usuário atualizado
    """
    current_user = User.query.get(request.user_id)
    if not current_user or current_user.role not in ('superadmin', 'mestre'):
        return jsonify({'error': 'Apenas superadministradores podem atualizar usuários'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Nenhum dado fornecido'}), 400

    if 'email' in data:
        existing = User.query.filter_by(email=data['email']).first()
        if existing and existing.id != user_id:
            return jsonify({'error': 'Email já está em uso'}), 409
        user.email = data['email']

    if 'sector_id' in data:
        user.sector_id = data['sector_id']

    if 'role' in data:
        if data['role'] == 'superadmin' and current_user.role != 'mestre':
            return jsonify({'error': 'Apenas o mestre pode definir papel superadmin'}), 403
        user.role = data['role']

    if 'is_active' in data:
        user.is_active = data['is_active']
    
    db.session.commit()
    
    # Registrar ação
    AuditLog.log_action(
        user_id=request.user_id,
        action='UPDATE_USER',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=f'Usuário atualizado: {user.username}'
    )
    
    return jsonify({
        'success': True,
        'message': 'Usuário atualizado com sucesso',
        'user': user.to_dict()
    }), 200

@auth_bp.route('/users/<int:user_id>', methods=['DELETE'])
@require_auth
def delete_user(user_id):
    """
    Excluir um usuário (apenas para admins)
    
    Cabeçalhos:
        - Authorization: Bearer <token> (deve ser admin)
    
    Retorna:
        - success: True se excluído
    """
    current_user = User.query.get(request.user_id)
    if not current_user or current_user.role not in ('superadmin', 'mestre'):
        return jsonify({'error': 'Apenas superadministradores podem excluir usuários'}), 403

    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404

    if user.role == 'mestre':
        return jsonify({'error': 'Não é possível excluir o mestre'}), 403

    if user.role == 'superadmin' and current_user.role != 'mestre':
        return jsonify({'error': 'Apenas o mestre pode excluir superadministradores'}), 403

    # Não permitir excluir a si mesmo
    if user_id == request.user_id:
        return jsonify({'error': 'Não é possível excluir sua própria conta'}), 400

    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    # Registrar ação
    AuditLog.log_action(
        user_id=request.user_id,
        action='DELETE_USER',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=f'Usuário excluído: {username}'
    )
    
    return jsonify({
        'success': True,
        'message': 'Usuário excluído com sucesso'
    }), 200

@auth_bp.route('/change-password', methods=['POST'])
@require_auth
def change_password():
    """
    Alterar senha do usuário atual
    
    Corpo da Requisição:
        - current_password: Senha atual
        - new_password: Nova senha
    
    Cabeçalhos:
        - Authorization: Bearer <token>
    
    Retorna:
        - success: True se alterada com sucesso
    """
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Nenhum dado fornecido'}), 400
    
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({'error': 'Senha atual e nova senha são obrigatórias'}), 400
    
    if len(new_password) < 6:
        return jsonify({'error': 'A nova senha deve ter pelo menos 6 caracteres'}), 400
    
    user = User.query.get(request.user_id)
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    
    # Verificar senha atual
    # Primeiro, tentar verificar com hash bcrypt
    if user.password_hash:
        if not user.check_password(current_password):
            return jsonify({'error': 'Senha atual incorreta'}), 401
    else:
        # Fallback: para usuários antigos sem hash, verificar se é igual ao username ou admin123
        if user.username == 'admin' and current_password != 'admin123':
            return jsonify({'error': 'Senha atual incorreta'}), 401
        elif current_password != user.username:
            return jsonify({'error': 'Senha atual incorreta'}), 401
    
    # Definir nova senha com hash
    user.set_password(new_password)
    db.session.commit()
    
    # Registrar ação
    AuditLog.log_action(
        user_id=user.id,
        action='CHANGE_PASSWORD',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details='Senha alterada com sucesso'
    )
    
    return jsonify({
        'success': True,
        'message': 'Senha alterada com sucesso'
    }), 200

@auth_bp.route('/reset-password/<int:user_id>', methods=['POST'])
@require_auth
def reset_password(user_id):
    """
    Resetar senha de um usuário (apenas para admins)
    A senha volta a ser igual ao username
    
    Cabeçalhos:
        - Authorization: Bearer <token> (deve ser admin)
    
    Retorna:
        - success: True se resetado
        - temporary_password: Senha temporária (igual ao username)
    """
    current_user = User.query.get(request.user_id)
    if not current_user or current_user.role not in ('admin', 'superadmin', 'mestre'):
        return jsonify({'error': 'Apenas administradores podem resetar senhas'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    
    # Resetar senha para o username
    user.password_hash = None
    user.must_change_password = True
    db.session.commit()
    
    # Registrar ação
    AuditLog.log_action(
        user_id=request.user_id,
        action='RESET_PASSWORD',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=f'Senha resetada do usuário: {user.username}'
    )
    
    return jsonify({
        'success': True,
        'message': f'Senha do usuário {user.username} foi resetada',
        'temporary_password': user.username,
        'note': 'O usuário deverá trocar a senha no próximo login'
    }), 200

@auth_bp.route('/set-temporary-password/<int:user_id>', methods=['POST'])
@require_auth
def set_temporary_password(user_id):
    """
    Definir uma senha temporária para um usuário (apenas para admins)
    Útil quando o usuário esqueceu a senha
    
    Corpo da Requisição:
        - temporary_password: Senha temporária (mínimo 6 caracteres)
    
    Cabeçalhos:
        - Authorization: Bearer <token> (deve ser admin)
    
    Retorna:
        - success: True se definida
    """
    current_user = User.query.get(request.user_id)
    if not current_user or current_user.role not in ('admin', 'superadmin', 'mestre'):
        return jsonify({'error': 'Apenas administradores podem definir senhas temporárias'}), 403
    
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Usuário não encontrado'}), 404
    
    data = request.get_json()
    if not data or 'temporary_password' not in data:
        return jsonify({'error': 'Senha temporária é obrigatória'}), 400
    
    temp_password = data.get('temporary_password')
    
    if len(temp_password) < 6:
        return jsonify({'error': 'A senha temporária deve ter pelo menos 6 caracteres'}), 400
    
    # Definir senha temporária
    user.set_password(temp_password)
    user.must_change_password = True
    db.session.commit()
    
    # Registrar ação
    AuditLog.log_action(
        user_id=request.user_id,
        action='SET_TEMPORARY_PASSWORD',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=f'Senha temporária definida para: {user.username}'
    )
    
    return jsonify({
        'success': True,
        'message': f'Senha temporária definida para {user.username}',
        'note': 'O usuário deverá trocar a senha no próximo login'
    }), 200

@auth_bp.route('/sector-access', methods=['GET'])
@require_auth
def list_sector_access():
    from app.models.sector_access import UserSectorAccess
    from app.models.sector import Sector
    accesses = UserSectorAccess.query.filter_by(user_id=request.user_id).all()
    result = []
    for a in accesses:
        s = db.session.get(Sector, a.sector_id)
        result.append({
            'id': a.id,
            'sector_id': a.sector_id,
            'sector_name': s.name if s else 'N/A',
            'granted_at': a.granted_at.isoformat() if a.granted_at else None
        })
    return jsonify({'sector_access': result}), 200

@auth_bp.route('/sector-access', methods=['POST'])
@require_auth
def grant_sector_access():
    if request.user_role not in ('admin', 'superadmin'):
        return jsonify({'error': 'Apenas administradores podem conceder acesso a setores'}), 403
    data = request.get_json()
    if not data or not data.get('user_id') or not data.get('sector_id'):
        return jsonify({'error': 'user_id e sector_id são obrigatórios'}), 400
    from app.models.sector_access import UserSectorAccess
    existing = UserSectorAccess.query.filter_by(
        user_id=data['user_id'], sector_id=data['sector_id']
    ).first()
    if existing:
        return jsonify({'error': 'Acesso já concedido'}), 409
    access = UserSectorAccess(user_id=data['user_id'], sector_id=data['sector_id'])
    db.session.add(access)
    db.session.commit()
    AuditLog.log_action(
        user_id=request.user_id,
        action='GRANT_SECTOR_ACCESS',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=f'Acesso ao setor {data["sector_id"]} concedido ao usuário {data["user_id"]}'
    )
    return jsonify({'success': True, 'message': 'Acesso concedido'}), 201

@auth_bp.route('/sector-access/<int:access_id>', methods=['DELETE'])
@require_auth
def revoke_sector_access(access_id):
    if request.user_role not in ('admin', 'superadmin'):
        return jsonify({'error': 'Apenas administradores podem revogar acesso a setores'}), 403
    from app.models.sector_access import UserSectorAccess
    access = UserSectorAccess.query.get(access_id)
    if not access:
        return jsonify({'error': 'Acesso não encontrado'}), 404
    db.session.delete(access)
    db.session.commit()
    AuditLog.log_action(
        user_id=request.user_id,
        action='REVOKE_SECTOR_ACCESS',
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        details=f'Acesso revogado: {access_id}'
    )
    return jsonify({'success': True, 'message': 'Acesso revogado'}), 200
